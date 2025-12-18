//src/ip-reputation.service.ts
import { Injectable, Logger, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';
import { EventLogService } from '../events/event.service';
import { SecurityMonitoringService } from '../security/security-monitor.service';
import { IPReputationScore, ReputationQueryOptions, ReputationUpdateResult, ThreatIndicator } from './types/reputation.types';
import { IP_REPUTATION_CONFIG, RISK_LEVEL_THRESHOLDS, THREAT_INDICATORS } from './constants/reputation.constants';
import { EventType } from '../events/event.types';
import { RedisService } from '../redis/redis.service';
import { Cron, CronExpression } from '@nestjs/schedule';
import * as Sentry from '@sentry/node';
import { normalizeIp } from '@/auth/utils/normalize.util';

@Injectable()
export class IPReputationService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(IPReputationService.name);
  private readonly cachePrefix = 'ip-reputation:';
  private readonly eventWindow = 5 * 60 * 1000; // 5 minutes for anomaly detection
  private readonly recentEvents = new Map<string, Date[]>();
  
  // Fallback cache if Redis is not available
  private readonly fallbackCache = new Map<string, { value: IPReputationScore; expiry: number }>();

  constructor(
    private readonly prisma: PrismaService,
    private readonly eventLog: EventLogService,
    private readonly securityMonitor: SecurityMonitoringService,
    private readonly redis: RedisService,
    private readonly config: ConfigService,
  ) {}

  async onModuleInit() {
    try {
      await this.initialize();
      this.logger.log('IP Reputation Service initialized');
    } catch (error) {
      // SECURITY: Ensure ALL initialization errors are properly reported
      this.logger.error('Failed to initialize IP Reputation Service', error);
      Sentry.captureException(error, {
        level: 'error',
        tags: { 
          component: 'ip-reputation', 
          phase: 'initialization',
          module: 'IPReputationService'
        },
        extra: {
          context: 'Service initialization failed',
          timestamp: new Date().toISOString()
        }
      });
      // SECURITY: Re-throw to prevent service from starting in degraded state
      throw error;
    }
  }
  
 
  async onModuleDestroy() {
    this.logger.log('IP Reputation Service destroyed');
  }

  private async initialize() {
    // Warm up cache with recent IPs
    await this.warmupCache();
    
    // Start background processes
    this.startAnomalyDetection();
  }

  /**
   * Get reputation score for an IP address
   */
  private isValidIP(ip: string): boolean {
    if (typeof ip !== 'string' || !ip) return false;
  
    // SECURITY: Comprehensive IP validation
    // Allow standard formats and also formats potentially created by maskIp (e.g. 127.0.0.x -> 127.0.0 after normalization)
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/; // Standard IPv4
    const ipv4IncompleteRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){1,3}$/; // e.g., 127, 127.0, 127.0.0 (from maskIp)
    const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/; // Standard IPv6
    const ipv6CompressedRegex = /^((?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*)?)::((?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*)?)$/; // Compressed IPv6
  
    return ipv4Regex.test(ip) || ipv4IncompleteRegex.test(ip) || ipv6Regex.test(ip) || ipv6CompressedRegex.test(ip) || ip === 'localhost';
  }

  async getReputation(ip: string): Promise<IPReputationScore | null> {
    // Add this log
    this.logger.log(`getReputation called with IP: "${ip}"`);

    // Normalize the IP first
    const normalizedIpForValidation = normalizeIp(ip);
    if (normalizedIpForValidation === null) {
      this.logger.warn(`IP normalization failed (null input after processing): ${ip}`);
      Sentry.captureMessage(`IP normalization failed (null input after processing): ${ip}`, 'warning');
      return null;
    }

    // SECURITY: Validate the *normalized* input before processing
    if (!this.isValidIP(normalizedIpForValidation)) {
      this.logger.warn(`Invalid IP address format after normalization: ${normalizedIpForValidation} (original: ${ip})`);
      Sentry.captureMessage(`Invalid IP address format after normalization: ${normalizedIpForValidation}`, 'warning');
      return null;
    }

    try {
      // First check cache using the ORIGINAL IP (as stored/retrieved)
      const cached = await this.getCachedReputation(ip);
      if (cached) return cached;

      // Query database using the ORIGINAL IP
      const score = await this.calculateReputation(ip); // Pass original IP for DB query

      // Cache the result using the ORIGINAL IP
      await this.setCachedReputation(score);

      return score;
    } catch (error) {
      this.logger.error(`Error getting reputation for IP ${ip} (normalized: ${normalizedIpForValidation}):`, error);
       Sentry.captureException(error, {
      level: 'error',
      tags: { component: 'ip-reputation', method: 'getReputation' },
      extra: { ip, normalizedIp: normalizedIpForValidation }
    });
      return null;
    }
  }

  private safeEventIteration(events: any[]): any[] {
    if (!Array.isArray(events)) return [];
    
    return events.filter(event => 
      event && 
      typeof event === 'object' && 
      event.type && 
      event.createdAt instanceof Date
    );
  }

  /**
   * Calculate reputation score based on event history
   */
  private async calculateReputation(ip: string): Promise<IPReputationScore> {
    this.logger.log(`calculateReputation called with IP: "${ip}"`);
    
    if (ip.includes('.x') || ip.includes('::')) {
      this.logger.warn(`Skipping reputation calculation for masked IP: ${ip}`);
      // Return a default reputation score for masked IPs
      return {
        ip,
        score: 0, // Neutral score for masked IPs
        riskLevel: 'LOW',
        totalEvents: 0,
        securityEvents: 0,
        lastUpdated: new Date(),
        eventCounts: {} as any,
        threatIndicators: [],
        reputationHistory: [],
        blocked: false,
        whitelisted: false,
        metadata: {
          lastEvent: null,
          firstEvent: null,
        },
      };
    }
    
    const normalizedIp = normalizeIp(ip);
    this.logger.log(`calculateReputation normalized IP: "${normalizedIp}" from original: "${ip}"`);
    if (normalizedIp === null) {
      throw new Error(`Invalid IP address: ${ip}`);
    }
    
    if (!this.isValidIP(normalizedIp)) {
      this.logger.error(`Normalized IP failed validation: "${normalizedIp}"`);
      throw new Error(`Invalid IP address: ${normalizedIp}`);
    }

    // Get events for this IP in the last 30 days
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    
    const events = await this.prisma.event.findMany({
      where: {
        ipAddress: ip,
        createdAt: { gte: thirtyDaysAgo },
      },
      orderBy: { createdAt: 'desc' },
    });

    const safeEvents = Array.isArray(events) ? events : [];
    // Calculate base score
    let score = 0;
    const eventCounts: Record<EventType, number> = {} as Record<EventType, number>;
    const threatIndicators: ThreatIndicator[] = [];

    // Initialize event counts
    Object.keys(IP_REPUTATION_CONFIG.scoring.weights).forEach(type => {
      eventCounts[type as EventType] = 0;
    });

    // Process events and calculate score
    for (const event of safeEvents) {
      if (!event || !event.type) continue;

      const eventType = event.type as EventType;
      const weight = IP_REPUTATION_CONFIG.scoring.weights[eventType] || 0;
      
      // Apply decay based on age (older events have less impact)
      const ageInDays = (Date.now() - event.createdAt.getTime()) / (24 * 60 * 60 * 1000);
      const decayMultiplier = Math.pow(IP_REPUTATION_CONFIG.scoring.decayRate, ageInDays);
      const weightedScore = weight * decayMultiplier;
      
      score += weightedScore;
      eventCounts[eventType] = (eventCounts[eventType] || 0) + 1;
    }

    // Apply threat indicators
    threatIndicators.push(...await this.detectThreatIndicators(ip, safeEvents));

    // Ensure score is within bounds
    score = Math.max(IP_REPUTATION_CONFIG.scoring.minScore, 
                    Math.min(IP_REPUTATION_CONFIG.scoring.maxScore, score));

    // Determine risk level
    const riskLevel = this.getRiskLevel(score);

    // Check if IP is blocked
    const isBlocked = await this.isIPBlocked(ip);
    const blockInfo = await this.getBlockInfo(ip);

    // Get reputation history
    const reputationHistory = await this.getReputationHistory(ip);

    return {
      ip,
      score,
      riskLevel,
      totalEvents: safeEvents.length,
      securityEvents: safeEvents.filter(e => e.severity === 'SECURITY' || e.severity === 'CRITICAL').length,
      lastUpdated: new Date(),
      eventCounts,
      threatIndicators,
      reputationHistory,
      blocked: isBlocked,
      blockReason: blockInfo?.reason,
      blockUntil: blockInfo?.expiresAt,
      whitelisted: await this.isIPWhitelisted(ip),
      metadata: {
        lastEvent: safeEvents[0]?.createdAt, 
        firstEvent: safeEvents[safeEvents.length - 1]?.createdAt,
      },
    };
  }

  /**
   * Update reputation based on new events
   */
  async updateReputation(ip: string, eventType: EventType): Promise<ReputationUpdateResult> {
   
    if (ip.includes('.x') || ip.includes('::')) {
      this.logger.warn(`Skipping reputation update for masked IP: ${ip}`);
      return {
        ip,
        previousScore: 0,
        newScore: 0,
        riskLevelChanged: false,
        actionTaken: 'NONE',
        reason: 'Masked IP - reputation not calculated',
      };
    }

    const previousScore = (await this.getReputation(ip))?.score || 0;
    const newScore = await this.calculateReputation(ip).then(r => r.score);
    
    const riskLevelChanged = this.getRiskLevel(previousScore) !== this.getRiskLevel(newScore);
    let actionTaken: 'NONE' | 'BLOCKED' | 'UNBLOCKED' | 'ALERTED' = 'NONE';
    let reason: string | undefined;

    // Check if blocking is needed
    if (IP_REPUTATION_CONFIG.blocking.autoBlock && !await this.isIPWhitelisted(ip)) {
      const riskLevel = this.getRiskLevel(newScore);
      
      if (riskLevel === 'CRITICAL' && !await this.isIPBlocked(ip)) {
        await this.blockIP(ip, 'CRITICAL_REPUTATION_SCORE', 
          IP_REPUTATION_CONFIG.blocking.blockDuration);
        actionTaken = 'BLOCKED';
        reason = 'Critical reputation score threshold exceeded';
      } else if (newScore < IP_REPUTATION_CONFIG.blocking.thresholds.medium && 
                 await this.isIPBlocked(ip)) {
        await this.unblockIP(ip);
        actionTaken = 'UNBLOCKED';
        reason = 'Reputation score improved below blocking threshold';
      } else if (riskLevel === 'HIGH' || riskLevel === 'CRITICAL') {
        actionTaken = 'ALERTED';
        reason = `High risk reputation score detected: ${newScore}`;
      }
    }

    // Update cache
    const updatedReputation = await this.calculateReputation(ip);
    await this.setCachedReputation(updatedReputation);

    return {
      ip,
      previousScore,
      newScore,
      riskLevelChanged,
      actionTaken,
      reason,
    };
  }

  /**
   * Block an IP address
   */
  async blockIP(ip: string, reason: string, durationMs?: number): Promise<void> {
    const actualDuration = durationMs || IP_REPUTATION_CONFIG.blocking.blockDuration;
    const expiresAt = new Date(Date.now() + actualDuration);
    
    await this.prisma.$transaction(async (tx) => {
      // Create or update block record
      await tx.iPBlock.upsert({
        where: { ip },
        update: {
          reason,
          expiresAt,
          blockedAt: new Date(),
        },
        create: {
          ip,
          reason,
          expiresAt,
          blockedAt: new Date(),
        },
      });

      // Log the block event
      await this.eventLog.logEvent('SECURITY_CSRF_ERROR', {
        ipAddress: ip,
        metadata: {
          reason: 'IP_BLOCKED',
          blockReason: reason,
          score: (await this.getReputation(ip))?.score,
        },
        severity: 'CRITICAL',
      });
    });

    this.logger.warn(`IP ${ip} blocked: ${reason}`);
    
    // Clear cache for this IP
    await this.clearCachedReputation(ip);
  }

  /**
   * Unblock an IP address
   */
  async unblockIP(ip: string): Promise<void> {
    await this.prisma.iPBlock.deleteMany({
      where: { ip, expiresAt: { gte: new Date() } },
    });

    this.logger.log(`IP ${ip} unblocked`);
    
    // Clear cache for this IP
    await this.clearCachedReputation(ip);
  }

  /**
   * Check if IP is blocked
   */
  async isIPBlocked(ip: string): Promise<boolean> {
    
    if (ip.includes('.x') || ip.includes('::')) {
      return false; // Masked IPs are not blocked by definition
    }
    
    const block = await this.prisma.iPBlock.findFirst({
      where: {
        ip,
        expiresAt: { gte: new Date() },
      },
    });
    // console.log('Available prisma models:', Object.keys(this.prisma));
console.log('ipReputation property exists:', 'ipReputation' in this.prisma);
    return !!block;
  }

  /**
   * Get block information for an IP
   */
  async getBlockInfo(ip: string) {

    if (ip.includes('.x') || ip.includes('::')) {
      return null; // Masked IPs cannot be blocked
    }
    
    return await this.prisma.iPBlock.findFirst({
      where: {
        ip,
        expiresAt: { gte: new Date() },
      },
    });
  }

  /**
   * Whitelist an IP address
   */
  async whitelistIP(ip: string, reason: string): Promise<void> {
    await this.prisma.iPWhitelist.upsert({
      where: { ip },
      update: { reason },
      create: { ip, reason },
    });

    // If currently blocked, unblock it
    if (await this.isIPBlocked(ip)) {
      await this.unblockIP(ip);
    }

    this.logger.log(`IP ${ip} whitelisted: ${reason}`);
    
    // Clear cache for this IP
    await this.clearCachedReputation(ip);
  }

  /**
   * Remove IP from whitelist
   */
  async removeWhitelistIP(ip: string): Promise<void> {
    await this.prisma.iPWhitelist.deleteMany({
      where: { ip },
    });

    this.logger.log(`IP ${ip} removed from whitelist`);
    
    // Clear cache for this IP
    await this.clearCachedReputation(ip);
  }

  /**
   * Check if IP is whitelisted
   */
  async isIPWhitelisted(ip: string): Promise<boolean> {
    const whitelist = await this.prisma.iPWhitelist.findFirst({
      where: { ip },
    });
    
    return !!whitelist;
  }

  /**
   * Query IPs by reputation criteria
   */
  async queryReputations(options: ReputationQueryOptions = {}): Promise<IPReputationScore[]> {
    const where: any = {};
    
    if (options.minScore !== undefined) {
      where.score = { gte: options.minScore };
    }
    if (options.maxScore !== undefined) {
      where.score = { ...where.score, lte: options.maxScore };
    }
    if (options.riskLevel && options.riskLevel.length > 0) {
      where.riskLevel = { in: options.riskLevel };
    }
    if (options.blockedOnly) {
      where.blocked = true;
    }

    // This would require a reputation summary table or aggregation
    // For now, we'll get IPs from recent events and calculate reputations
    const daysBack = options.daysBack || 7;
    const sinceDate = new Date(Date.now() - daysBack * 24 * 60 * 60 * 1000);
    
    const ips = await this.prisma.event.findMany({
      where: {
        ipAddress: { not: null },
        createdAt: { gte: sinceDate },
      },
      select: { ipAddress: true },
      distinct: ['ipAddress'],
      take: 1000, // Limit to prevent massive queries
    });

    const results: IPReputationScore[] = [];
    for (const { ipAddress } of ips) {
      if (ipAddress) {
        const reputation = await this.getReputation(ipAddress);
        if (reputation) {
          // Apply additional filters
          if (options.minScore !== undefined && reputation.score < options.minScore) continue;
          if (options.maxScore !== undefined && reputation.score > options.maxScore) continue;
          if (options.riskLevel && !options.riskLevel.includes(reputation.riskLevel)) continue;
          if (options.blockedOnly && !reputation.blocked) continue;
          
          results.push(reputation);
        }
      }
    }

    return results.sort((a, b) => b.score - a.score);
  }

  /**
   * Get reputation history for an IP
   */
  private async getReputationHistory(ip: string): Promise<any[]> {
    // This would come from a reputation history table
    // For now, return empty array - would need to implement historical tracking
    return [];
  }

  /**
   * Detect threat indicators for an IP
   */
  private async detectThreatIndicators(ip: string, events: any[]): Promise<ThreatIndicator[]> {
    const safeEvents = Array.isArray(events) ? events : [];
    const threats: ThreatIndicator[] = [];
    const now = Date.now();
    
     // Check for brute force attempts (failed logins in short time)
  const failedEvents = safeEvents.filter(e => 
    e && e.type && (
      e.type === 'OTP_FAILED' || 
      e.type === 'AUTH_JWT_FAILURE' || 
      e.type === 'REFRESH_FAILED'
    )
  );
    
    if (failedEvents.length >= THREAT_INDICATORS.BRUTE_FORCE.threshold) {
      const recentFailed = failedEvents.filter(e => 
        now - e.createdAt.getTime() <= THREAT_INDICATORS.BRUTE_FORCE.window
      );
      
      if (recentFailed.length >= THREAT_INDICATORS.BRUTE_FORCE.threshold) {
        threats.push({
          type: 'BRUTE_FORCE',
          severity: THREAT_INDICATORS.BRUTE_FORCE.severity,
          evidence: `Detected ${recentFailed.length} failed attempts in ${THREAT_INDICATORS.BRUTE_FORCE.window / 1000}s`,
          timestamp: new Date(),
          scoreImpact: THREAT_INDICATORS.BRUTE_FORCE.scoreImpact,
        });
      }
    }

    // Add more threat detection logic here...
    // Geo-risk analysis, behavioral analysis, etc.

    return threats;
  }

  /**
   * Get risk level based on score
   */
  private getRiskLevel(score: number): IPReputationScore['riskLevel'] {
    if (score >= RISK_LEVEL_THRESHOLDS.CRITICAL.min) return 'CRITICAL';
    if (score >= RISK_LEVEL_THRESHOLDS.HIGH.min) return 'HIGH';
    if (score >= RISK_LEVEL_THRESHOLDS.MEDIUM.min) return 'MEDIUM';
    return 'LOW';
  }

  /**
   * Cache operations with fallback
   */
  private async getCachedReputation(ip: string): Promise<IPReputationScore | null> {
    try {
      // Try Redis first
      const cachedRedis = await this.redis.get(`${this.cachePrefix}${ip}`);
      if (cachedRedis) {
        const cachedReputation: IPReputationScore = JSON.parse(cachedRedis);
        
        // --- FIX: Rehydrate date strings into Date objects ---
        if (cachedReputation.lastUpdated) {
          cachedReputation.lastUpdated = new Date(cachedReputation.lastUpdated);
        }
        if (cachedReputation.metadata?.lastEvent) {
          cachedReputation.metadata.lastEvent = new Date(cachedReputation.metadata.lastEvent);
        }
        if (cachedReputation.metadata?.firstEvent) {
          cachedReputation.metadata.firstEvent = new Date(cachedReputation.metadata.firstEvent);
        }
        if (cachedReputation.blockUntil) {
            cachedReputation.blockUntil = new Date(cachedReputation.blockUntil);
        }
        // If you have date objects in reputationHistory, you must iterate and rehydrate those too.

        return cachedReputation;
      }
      
      // Fallback to in-memory cache (this stores Date objects correctly already)
      const cached = this.fallbackCache.get(`${this.cachePrefix}${ip}`);
      if (cached) {
        if (cached.expiry && Date.now() > cached.expiry) {
          this.fallbackCache.delete(`${this.cachePrefix}${ip}`);
          return null;
        }
        return cached.value;
      }
      
      return null;
    } catch (error) {
      this.logger.warn(`Cache get error for IP ${ip}:`, error);
      return null;
    }
  }

  private async setCachedReputation(reputation: IPReputationScore): Promise<void> {
    try {
      // Set in Redis
      await this.redis.setex(
        `${this.cachePrefix}${reputation.ip}`,
        300, // 5 minutes TTL
        JSON.stringify(reputation)
      );
    } catch (error) {
      this.logger.warn(`Cache set error for IP ${reputation.ip}, using fallback:`, error);
      
      // Fallback to in-memory cache
      const expiry = Date.now() + (300 * 1000); // 5 minutes
      this.fallbackCache.set(`${this.cachePrefix}${reputation.ip}`, {
        value: reputation,
        expiry,
      });
    }
  }

  private async clearCachedReputation(ip: string): Promise<void> {
    try {
      // Clear from Redis
      await this.redis.del(`${this.cachePrefix}${ip}`);
    } catch (error) {
      this.logger.warn(`Cache clear error for IP ${ip}:`, error);
    }
    
    // Clear from fallback cache
    this.fallbackCache.delete(`${this.cachePrefix}${ip}`);
  }

  private async warmupCache(): Promise<void> {
    try {
      const highRiskIPs = await this.prisma.event.findMany({
        where: {
          ipAddress: { not: null },
          type: { in: ['TOKEN_REUSE', 'SECURITY_CSRF_MISMATCH', 'AUTH_JWT_FAILURE'] },
          createdAt: { gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) },
        },
        select: { ipAddress: true },
        distinct: ['ipAddress'],
        take: 100,
      });
  
      for (const { ipAddress } of highRiskIPs) {
        if (ipAddress) {
          try {
            const reputation = await this.getReputation(ipAddress);
            if (reputation) {
              await this.setCachedReputation(reputation);
            }
          } catch (ipError) {
            // Log individual IP errors but don't stop the entire warmup
            this.logger.warn(`Failed to warmup cache for IP ${ipAddress}:`, ipError);
          }
        }
      }
    } catch (error) {
      this.logger.error('Cache warmup error:', error);
      // SECURITY: Re-throw to ensure monitoring systems are notified
      throw error;
    }
  }

  /**
   * Anomaly detection
   */
  private startAnomalyDetection(): void {
    // Track request patterns for anomaly detection
    this.eventLog.event$.subscribe(async (event) => {
      if (event.ipAddress) {
        this.trackRequestPattern(event.ipAddress);
        await this.updateReputation(event.ipAddress, event.type);
      }
    });
  }

  private trackRequestPattern(ip: string): void {
    const now = Date.now();
    const events = this.recentEvents.get(ip) || [];
    
    // Remove events older than our window
    const recent = events.filter(timestamp => now - timestamp.getTime() <= this.eventWindow);
    recent.push(new Date());
    
    this.recentEvents.set(ip, recent);
  }

  /**
   * Cleanup old data
   */
  @Cron(CronExpression.EVERY_6_HOURS)
  async cleanup(): Promise<void> {
    this.logger.log('Starting IP reputation cleanup');
    
    try {
      // Remove expired blocks
      await this.prisma.iPBlock.deleteMany({
        where: { expiresAt: { lt: new Date() } },
      });

      // Clear old request patterns
      const cutoff = Date.now() - this.eventWindow;
      for (const [ip, events] of this.recentEvents.entries()) {
        const recent = events.filter(timestamp => timestamp.getTime() > cutoff);
        if (recent.length === 0) {
          this.recentEvents.delete(ip);
        } else {
          this.recentEvents.set(ip, recent);
        }
      }

      this.logger.log('IP reputation cleanup completed');
    } catch (error) {
      this.logger.error('IP reputation cleanup error:', error);
      Sentry.captureException(error, {
        level: 'error',
        tags: { component: 'ip-reputation', method: 'getReputation' },
             });
    }
  }

  /**
   * Reset reputation for an IP
   */
  async resetReputation(ip: string): Promise<void> {
    // This would reset the reputation to baseline
    // In practice, you might want to keep some history
    await this.clearCachedReputation(ip);
    
    // Log the reset
    await this.eventLog.logEvent('INTERNAL_ERROR', {
      ipAddress: ip,
      metadata: { reason: 'REPUTATION_RESET' },
      severity: 'INFO',
    });
  }
}