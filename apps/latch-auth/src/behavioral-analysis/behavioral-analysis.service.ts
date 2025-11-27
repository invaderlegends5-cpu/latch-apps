import { Injectable, Logger, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';
import { EventLogService } from '../events/event.service';
import { SecurityMonitoringService } from '../security/security-monitor.service';
import { IPReputationService } from '../ip-reputation/ip-reputation.service';
import { DeviceFingerprintingService } from '../device-fingerprinting/device-fingerprinting.service';
import { 
  RequestPattern, 
  BehavioralSession, 
  BehavioralProfile, 
  AnomalyDetectionResult, 
  TimingAnalysis,
  NavigationAnalysis,
  BehavioralThreat,
  SuspiciousIndicator
} from './types/behavior.types';
import { EventType } from '../events/event.types';
import * as Sentry from '@sentry/node';

@Injectable()
export class BehavioralAnalysisService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(BehavioralAnalysisService.name);
  private readonly behavioralSessions = new Map<string, BehavioralSession>();
  private readonly behavioralProfiles = new Map<string, BehavioralProfile>();
  private readonly requestHistory = new Map<string, RequestPattern[]>();
  private readonly threatCache = new Map<string, BehavioralThreat>();
  private readonly ipSessionMap = new Map<string, Set<string>>(); // Track sessions per IP
  private readonly userSessionMap = new Map<string, Set<string>>(); // Track sessions per user
  
  // Configuration
  private  config = {
    // Timing analysis thresholds
    minHumanInterval: 200, // Minimum ms between requests for human-like behavior
    
    maxBotInterval: 75, // Maximum ms between requests for bot-like behavior
    intervalEntropyThreshold: 0.3, // Below this = too predictable (bot-like)
    
    // Risk scoring weights
    timingAnomalyWeight: 0.5,
    navigationAnomalyWeight: 0.15,
    rateAnomalyWeight: 0.2,
    ipAnomalyWeight: 0.15,
    
    // Behavioral thresholds
    riskScoreThresholds: {
      low: 0.2,
      medium: 0.4,
      high: 0.7,
      critical: 0.9,
    },
    
    // Profile update frequency
    profileUpdateInterval: 24 * 60 * 60 * 1000, // 24 hours
    
    // History retention
    maxRequestHistory: 1000,
    sessionRetention: 60 * 60 * 1000, // 1 hour
    maxSessionsPerIP: 10, // Max concurrent sessions per IP
    maxSessionsPerUser: 5, // Max concurrent sessions per user

    // Navigation sequence limit ---
    maxNavigationSequenceLength: 50, // Limits the URLs stored per session
  };

  constructor(
    private readonly prisma: PrismaService,
    private readonly eventLog: EventLogService,
    private readonly securityMonitor: SecurityMonitoringService,
    private readonly ipReputation: IPReputationService,
    private readonly deviceFingerprinting: DeviceFingerprintingService,
    private readonly configService: ConfigService,
  ) {
    this.synchronizeConfiguration();
  }

  async onModuleInit() {
    // this.synchronizeConfiguration();
    await this.initialize();
    this.logger.log('Behavioral Analysis Service initialized');
  }

  private synchronizeConfiguration() {
    const thresholds = this.configService.get('riskScoreThresholds');
    if (thresholds) {
        Object.assign(this.config.riskScoreThresholds, thresholds);
    }
    // Synchronize the navigation length setting
    const navLength = this.configService.get('maxNavigationSequenceLength');
    if (navLength !== undefined && navLength !== null) {
        this.config.maxNavigationSequenceLength = navLength;
    }
     }

  async onModuleDestroy() {
    this.logger.log('Behavioral Analysis Service destroyed');
  }

  private async initialize() {
    // Load existing behavioral profiles
    await this.loadBehavioralProfiles();
    
    // Set up cleanup intervals
    this.startCleanupIntervals();
  }

  /**
   * Analyze a request for behavioral anomalies
   */
  async analyzeRequest(
    userId: string | null,
    sessionId: string | null,
    ipAddress: string | null,
    userAgent: string | null,
    method: string,
    url: string,
    responseTime: number = 0,
  ): Promise<AnomalyDetectionResult> {
    try {
      const requestPattern: RequestPattern = {
        timestamp: new Date(),
        method,
        url,
        userAgent,
        ipAddress,
        sessionId,
        userId,
        responseTime,
        userAgentChange: false,
        ipChange: false,
      };

      // Get or create behavioral session
      const sessionKey = sessionId || `${ipAddress || 'unknown'}-${userId || 'unknown'}`;
      let session = this.behavioralSessions.get(sessionKey);
      
      if (!session) {
        session = this.createBehavioralSession(requestPattern);
        this.behavioralSessions.set(sessionKey, session);
        
        // Update session tracking maps
        if (ipAddress) {
          if (!this.ipSessionMap.has(ipAddress)) {
            this.ipSessionMap.set(ipAddress, new Set());
          }
          this.ipSessionMap.get(ipAddress)!.add(sessionKey);
        }
        
        if (userId) {
          if (!this.userSessionMap.has(userId)) {
            this.userSessionMap.set(userId, new Set());
          }
          this.userSessionMap.get(userId)!.add(sessionKey);
        }
      } else {
        session = this.updateBehavioralSession(session, requestPattern);
        this.behavioralSessions.set(sessionKey, session);
      }

      // Track request history for this session
      this.trackRequestHistory(sessionKey, requestPattern);

      // Perform comprehensive analysis
      const timingAnalysis = this.analyzeTiming(session, sessionKey);
      const navigationAnalysis = this.analyzeNavigation(session);
      const rateAnalysis = this.analyzeRate(session, sessionKey);
      const ipAnalysis = await this.analyzeIPBehavior(session, sessionKey);
      const sessionAnalysis = this.analyzeSessionBehavior(session, ipAddress, userId);

      // Calculate overall risk score
      const riskScore = this.calculateRiskScore(
        timingAnalysis,
        navigationAnalysis,
        rateAnalysis,
        ipAnalysis,
        sessionAnalysis
      );

           // Determine anomaly status
      const isAnomalous = riskScore >= this.config.riskScoreThresholds.medium;
      const anomalyType = this.determineAnomalyType(timingAnalysis, navigationAnalysis, rateAnalysis);
      const severity = this.getRiskLevel(riskScore);

      // Create threat if high risk
      if (riskScore >= this.config.riskScoreThresholds.high) {
        await this.createThreatAlert(session, riskScore, severity, sessionAnalysis.indicators);
      }

      // Log behavioral analysis
      await this.eventLog.logEvent('SECURITY_STATUS_CHECKED', {
        userId: session.userId,
        tenantId: null, // Could be enhanced with tenant context
        metadata: {
          analysisType: 'BEHAVIORAL',
          riskScore,
          severity,
          timingAnomaly: timingAnalysis.isHumanLike === false,
          navigationAnomaly: navigationAnalysis.anomalyDetected,
          rateAnomaly: rateAnalysis.isAnomalous,
          ipAnomaly: ipAnalysis.isAnomalous,
          sessionAnomaly: sessionAnalysis.isAnomalous,
        },
        ipAddress: session.ipAddress,
        userAgent: session.userAgent,
        severity: this.mapRiskLevelToEventSeverity(severity),
      });

      return {
        isAnomalous,
        confidence: riskScore,
        anomalyType,
        severity,
        indicators: [
          ...timingAnalysis.isHumanLike === false ? ['Timing anomaly detected'] : [],
          ...navigationAnalysis.anomalyDetected ? ['Navigation anomaly detected'] : [],
          ...rateAnalysis.isAnomalous ? ['Rate anomaly detected'] : [],
          ...ipAnalysis.isAnomalous ? ['IP behavior anomaly detected'] : [],
          ...sessionAnalysis.isAnomalous ? ['Session behavior anomaly detected'] : [],
        ],
        riskScore,
        recommendation: riskScore >= this.config.riskScoreThresholds.critical ? 'BLOCK' :
                       riskScore >= this.config.riskScoreThresholds.high ? 'CHALLENGE' : 'ALLOW',
      };
    } catch (error) {
      this.logger.error('Error in behavioral analysis:', error);
      Sentry.captureException(error);
      return this.getDefaultAnomalyResult();
    }
  }

  /**
   * Analyze timing patterns for bot-like behavior
   */
  private analyzeTiming(session: BehavioralSession, sessionKey: string): TimingAnalysis {
    const intervals = this.calculateRequestIntervals(sessionKey);
    
    if (intervals.length < 2) {
      return {
        intervals,
        isHumanLike: true,
        entropy: 1,
        patterns: {
          regular: false,
          tooFast: false,
          tooConsistent: false,
        },
      };
    }

    // Calculate statistics
    const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const variance = intervals.reduce((a, b) => a + Math.pow(b - avgInterval, 2), 0) / intervals.length;
    const stdDev = Math.sqrt(variance);
    
    // Calculate entropy (randomness in timing)
    const entropy = this.calculateEntropy(intervals);
    
    // Check for bot-like patterns
    const tooFast = avgInterval < this.config.minHumanInterval;
    const tooConsistent = stdDev < 10; // Very consistent intervals = bot-like
    const regularPattern = this.detectRegularPatterns(intervals);
    
    const isHumanLike = !tooFast && !tooConsistent && !regularPattern && entropy > this.config.intervalEntropyThreshold;

    return {
      intervals,
      isHumanLike,
      entropy,
      patterns: {
        regular: regularPattern,
        tooFast,
        tooConsistent,
      },
    };
  }

  /**
   * Analyze navigation patterns for unusual sequences
   */
  private analyzeNavigation(session: BehavioralSession): NavigationAnalysis {
    const sequence = session.navigationSequence;
    
    // For now, return basic analysis - this could be enhanced with ML
    const deviationScore = 0; // Placeholder - would need actual expected paths
    const anomalyDetected = false; // Placeholder
    
    return {
      sequence,
      isExpected: true,
      deviationScore,
      commonPaths: [],
      anomalyDetected,
      expectedTransitions: sequence.length - 1,
      unexpectedTransitions: 0,
    };
  }

  /**
   * Analyze request rate for unusual patterns
   */
  private analyzeRate(session: BehavioralSession, sessionKey: string): { isAnomalous: boolean; rate: number; burstiness: number } {
    const recentRequests = this.getRecentRequests(sessionKey, 60 * 1000); // Last 60 seconds
    const rate = recentRequests.length;
    
    // Calculate burstiness based on request clustering
    const burstiness = this.calculateRateBurstiness(recentRequests);
    
    // Consider it anomalous if rate is too high or too bursty
    const isAnomalous = rate > 20 || burstiness > 0.8; // Adjust thresholds as needed

    return { isAnomalous, rate, burstiness };
  }

  /**
   * Analyze IP behavior patterns
   */
  private async analyzeIPBehavior(session: BehavioralSession, sessionKey: string): Promise<{ isAnomalous: boolean; indicators: string[] }> {
    const indicators: string[] = [];
    
    if (session.ipAddress && session.ipAddress !== 'unknown') {
      // Check IP reputation
      const isBlocked = await this.ipReputation.isIPBlocked(session.ipAddress);
      if (isBlocked) {
        indicators.push('IP is blocked');
      }

      // Check session count for this IP
      const sessionCount = this.ipSessionMap.get(session.ipAddress)?.size || 0;
      if (sessionCount > this.config.maxSessionsPerIP) {
        indicators.push(`Too many sessions from single IP (${sessionCount})`);
      }
    }

    return {
      isAnomalous: indicators.length > 0,
      indicators,
    };
  }

  /**
   * Analyze session behavior (multiple sessions, concurrent access, etc.)
   */
  private analyzeSessionBehavior(session: BehavioralSession, ipAddress: string | null, userId: string | null): { isAnomalous: boolean; indicators: SuspiciousIndicator[] } {
    const indicators: SuspiciousIndicator[] = [];

    if (userId && ipAddress) {
      // Check concurrent sessions for this user
      const userSessionCount = this.userSessionMap.get(userId)?.size || 0;
      if (userSessionCount > this.config.maxSessionsPerUser) {
        indicators.push({
          type: 'RATE_ANOMALY',
          severity: 'HIGH',
          evidence: `Too many concurrent sessions for user (${userSessionCount})`,
          timestamp: new Date(),
          scoreImpact: 0.2,
        });
      }

      // Check if this IP has been used from multiple locations recently
      // This would require more sophisticated location tracking
    }

    return {
      isAnomalous: indicators.length > 0,
      indicators,
    };
  }

  /**
   * Calculate risk score based on all analysis results
   */
  private calculateRiskScore(
    timing: TimingAnalysis,
    navigation: NavigationAnalysis,
    rate: { isAnomalous: boolean; rate: number; burstiness: number },
    ip: { isAnomalous: boolean; indicators: string[] },
    session: { isAnomalous: boolean; indicators: SuspiciousIndicator[] }
  ): number {
    let score = 0;

    // Timing anomaly contributes to risk
    if (!timing.isHumanLike) {
      score += this.config.timingAnomalyWeight;
         }

    // Navigation anomaly contributes to risk
    if (navigation.anomalyDetected) {
      score += this.config.navigationAnomalyWeight;
    }

    // Rate anomaly contributes to risk
    if (rate.isAnomalous) {
      score += this.config.rateAnomalyWeight;
    }

    // IP anomaly contributes to risk
    if (ip.isAnomalous) {
      score += this.config.ipAnomalyWeight;
    }

    // Session anomaly contributes to risk
    if (session.isAnomalous) {
      score += 0.1; // Lower weight for session anomalies
    }

    // Cap the score between 0 and 1
    const finalScore = Math.min(1, Math.max(0, score));
       return finalScore;
  }

  /**
   * Create threat alert for high-risk behavior
   */
  private async createThreatAlert(session: BehavioralSession, riskScore: number, severity: string, additionalIndicators: SuspiciousIndicator[] = []): Promise<void> {
    const threat: BehavioralThreat = {
      id: `behavioral-threat-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      userId: session.userId,
      sessionId: session.sessionId,
      threatType: 'SUSPICIOUS_BEHAVIOR',
      severity: severity as 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL',
      indicators: [...this.getThreatIndicators(session), ...additionalIndicators],
      totalRiskScore: riskScore,
      detectionTimestamp: new Date(),
      resolved: false,
    };

    this.threatCache.set(threat.id, threat);

    // Log the threat
    await this.eventLog.logEvent('SECURITY_CSRF_ERROR', {
      userId: session.userId,
      tenantId: null,
      metadata: {
        reason: 'behavioral_threat_detected',
        threatId: threat.id,
        riskScore,
        severity,
        sessionInfo: {
          totalRequests: session.totalRequests,
          requestPattern: session.requestIntervalStats,
          navigationSequence: session.navigationSequence,
        },
      },
      ipAddress: session.ipAddress,
      userAgent: session.userAgent,
      severity: this.mapRiskLevelToEventSeverity(severity as any),
    });

    this.logger.warn(`Behavioral threat detected:`, threat);
  }

  /**
   * Get threat indicators for a session
   */
  private getThreatIndicators(session: BehavioralSession): SuspiciousIndicator[] {
    const indicators: SuspiciousIndicator[] = [];

    // Add indicators based on session analysis
    if (session.requestIntervalStats.stdDev < 10) {
      indicators.push({
        type: 'TIMING_ANOMALY',
        severity: 'HIGH',
        evidence: 'Very consistent request intervals',
        timestamp: new Date(),
        scoreImpact: 0.3,
      });
    }

    return indicators;
  }

  /**
   * Calculate entropy of request intervals (randomness)
   */
  private calculateEntropy(intervals: number[]): number {
    if (intervals.length === 0) return 0;

    // Create frequency map
    const freqMap = new Map<number, number>();
    for (const interval of intervals) {
      // Group similar intervals to avoid over-precision
      const roundedInterval = Math.round(interval / 100) * 100; // Group by 100ms
      freqMap.set(roundedInterval, (freqMap.get(roundedInterval) || 0) + 1);
    }

    // Calculate probabilities and entropy
    let entropy = 0;
    const total = intervals.length;
    
    for (const count of freqMap.values()) {
      const probability = count / total;
      if (probability > 0) {
        entropy -= probability * Math.log2(probability);
      }
    }

    // Normalize entropy (0-1 scale)
    const maxEntropy = Math.log2(freqMap.size);
    return maxEntropy > 0 ? entropy / maxEntropy : 0;
  }

  /**
   * Calculate request intervals from request history
   */
  private calculateRequestIntervals(sessionKey: string): number[] {
    const history = this.requestHistory.get(sessionKey) || [];
    if (history.length < 2) return [];

    const intervals: number[] = [];
    for (let i = 1; i < history.length; i++) {
      const interval = history[i].timestamp.getTime() - history[i-1].timestamp.getTime();
      if (interval > 0) { // Only consider positive intervals
        intervals.push(interval);
      }
    }

    return intervals;
  }

  /**
   * Detect regular patterns in intervals
   */
  private detectRegularPatterns(intervals: number[]): boolean {
    if (intervals.length < 3) return false;

    // Check if intervals are too similar (indicating automation)
    const avg = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const variance = intervals.reduce((a, b) => a + Math.pow(b - avg, 2), 0) / intervals.length;
    const stdDev = Math.sqrt(variance);

    return stdDev < 5; // Very low standard deviation = regular pattern
  }

  /**
   * Calculate burstiness of requests
   */
  private calculateRateBurstiness(requests: RequestPattern[]): number {
    if (requests.length < 2) return 0;

    // Calculate time between requests and measure clustering
    const intervals: number[] = [];
    for (let i = 1; i < requests.length; i++) {
      intervals.push(requests[i].timestamp.getTime() - requests[i-1].timestamp.getTime());
    }

    if (intervals.length === 0) return 0;

    // Calculate coefficient of variation (std dev / mean)
    const avg = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    if (avg === 0) return 1; // High burstiness if no time between requests

    const variance = intervals.reduce((a, b) => a + Math.pow(b - avg, 2), 0) / intervals.length;
    const stdDev = Math.sqrt(variance);
    
    return stdDev / avg; // Higher values = more bursty
  }

  /**
   * Get recent requests for a session
   */
  private getRecentRequests(sessionKey: string, timeWindowMs: number): RequestPattern[] {
    const history = this.requestHistory.get(sessionKey) || [];
    const now = Date.now();
    return history.filter(req => now - req.timestamp.getTime() <= timeWindowMs);
  }

  /**
   * Create new behavioral session
   */
  private createBehavioralSession(request: RequestPattern): BehavioralSession {
    return {
      sessionId: request.sessionId || `session-${Date.now()}`,
      userId: request.userId || 'unknown',
      ipAddress: request.ipAddress || 'unknown',
      userAgent: request.userAgent || 'unknown',
      firstRequest: request.timestamp,
      lastRequest: request.timestamp,
      totalRequests: 1,
      requestIntervalStats: {
        mean: 0,
        stdDev: 0,
        min: 0,
        max: 0,
      },
      navigationSequence: [request.url],
      suspiciousIndicators: [],
      riskScore: 0,
      riskLevel: 'LOW',
    };
  }

  /**
   * Update existing behavioral session
   */
  private updateBehavioralSession(session: BehavioralSession, request: RequestPattern): BehavioralSession {
    session.lastRequest = request.timestamp;
    session.totalRequests++;
    session.navigationSequence.push(request.url);
    
    const MAX_LENGTH = this.config.maxNavigationSequenceLength || 50;

    // Keep navigation sequence reasonable size
    if (session.navigationSequence.length > MAX_LENGTH) {
            session.navigationSequence.shift(); 
    }

    return session;
  }

  /**
   * Track request history for behavioral analysis
   */
  private trackRequestHistory(sessionKey: string, request: RequestPattern): void {
    if (!this.requestHistory.has(sessionKey)) {
      this.requestHistory.set(sessionKey, []);
    }

    const history = this.requestHistory.get(sessionKey)!;
    history.push(request);

    // Keep history size reasonable
    if (history.length > this.config.maxRequestHistory) {
      this.requestHistory.set(sessionKey, history.slice(-this.config.maxRequestHistory));
    }
    // Ensure the navigation sequence is limited
  const session = this.behavioralSessions.get(sessionKey);
  if (session) {

    if (session.navigationSequence.length > this.config.maxNavigationSequenceLength) {
      
            // Use splice to keep only the most recent N elements. 
      // N = this.config.maxNavigationSequenceLength (which is 50 in your test config)
      const itemsToRemove = session.navigationSequence.length - this.config.maxNavigationSequenceLength;
      session.navigationSequence.splice(0, itemsToRemove); 
      // After this, the array length is 50, and the first element is the 51st original element (page 50).
   
    }
  }
  }

  /**
   * Load existing behavioral profiles from database
   */
  private async loadBehavioralProfiles(): Promise<void> {
    try {
      // Load historical data to build behavioral profiles
      // This would query the Event table for historical patterns
      const recentEvents = await this.prisma.event.findMany({
        where: {
          createdAt: { gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) }, // Last 30 days
        },
        orderBy: { createdAt: 'desc' },
        take: 10000, // Limit to avoid memory issues
      });

      // Build profiles based on historical data
      for (const event of recentEvents) {
        if (event.userId) {
          await this.updateBehavioralProfile(event.userId, event);
        }
      }
    } catch (error) {
      this.logger.error('Error loading behavioral profiles:', error);
    }
  }

  /**
   * Update behavioral profile for a user
   */
  private async updateBehavioralProfile(userId: string, event: any): Promise<void> {
    // This would update the user's behavioral profile based on the event
    // For now, we'll just ensure the profile exists
    if (!this.behavioralProfiles.has(userId)) {
      this.behavioralProfiles.set(userId, this.createDefaultProfile(userId));
    }
  }

  /**
   * Create default behavioral profile
   */
  private createDefaultProfile(userId: string): BehavioralProfile {
    return {
      userId,
      requestPattern: {
        avgInterval: 2000, // 2 seconds average
        intervalStdDev: 1000,
        preferredUserAgents: [],
        commonIps: [],
        typicalNavigation: [],
        peakActivityHours: [9, 10, 11, 14, 15, 16], // Typical business hours
      },
      lastUpdated: new Date(),
    };
  }

  /**
   * Start cleanup intervals
   */
  private startCleanupIntervals(): void {
    // Clean up old sessions periodically
    setInterval(() => {
      this.cleanupOldSessions();
    }, this.config.sessionRetention);

    // Update profiles periodically
    setInterval(() => {
      this.updateBehavioralProfiles();
    }, this.config.profileUpdateInterval);
  }

  /**
   * Clean up old behavioral sessions
   */
  private cleanupOldSessions(): void {
    const cutoff = Date.now() - this.config.sessionRetention;
    
    // Clean up behavioral sessions
    for (const [key, session] of this.behavioralSessions.entries()) {
      if (session.lastRequest.getTime() < cutoff) {
        this.behavioralSessions.delete(key);
        
        // Also clean up from tracking maps
        if (session.ipAddress && session.ipAddress !== 'unknown') {
          const ipSessions = this.ipSessionMap.get(session.ipAddress);
          if (ipSessions) {
            ipSessions.delete(key);
            if (ipSessions.size === 0) {
              this.ipSessionMap.delete(session.ipAddress);
            }
          }
        }
        
        if (session.userId && session.userId !== 'unknown') {
          const userSessions = this.userSessionMap.get(session.userId);
          if (userSessions) {
            userSessions.delete(key);
            if (userSessions.size === 0) {
              this.userSessionMap.delete(session.userId);
            }
          }
        }
      }
    }

    // Clean up old request histories
    for (const [key, history] of this.requestHistory.entries()) {
      const recentHistory = history.filter(req => Date.now() - req.timestamp.getTime() <= this.config.sessionRetention);
      if (recentHistory.length === 0) {
        this.requestHistory.delete(key);
      } else {
        this.requestHistory.set(key, recentHistory);
      }
    }
  }

  /**
   * Update behavioral profiles with recent data
   */
  private async updateBehavioralProfiles(): Promise<void> {
    // This would update all profiles with recent activity data
    // Implementation would depend on your specific requirements
  }

  /**
   * Determine anomaly type based on analysis results
   */
  private determineAnomalyType(
    timing: TimingAnalysis,
    navigation: NavigationAnalysis,
    rate: { isAnomalous: boolean; rate: number; burstiness: number }
  ): 'RATE' | 'NAVIGATION' | 'TIMING' | 'BEHAVIORAL' {
    if (rate.isAnomalous) return 'RATE';
    if (navigation.anomalyDetected) return 'NAVIGATION';
    if (!timing.isHumanLike) return 'TIMING';
    return 'BEHAVIORAL';
  }

  /**
   * Get risk level from score
   */
  private getRiskLevel(score: number): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
    if (score >= this.config.riskScoreThresholds.critical) return 'CRITICAL';
    if (score >= this.config.riskScoreThresholds.high) return 'HIGH';
    if (score >= this.config.riskScoreThresholds.medium) return 'MEDIUM';
    return 'LOW';
  }

  /**
   * Map risk level to event severity
   */
  private mapRiskLevelToEventSeverity(level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'): 'INFO' | 'SECURITY' | 'CRITICAL' | 'ERROR' {
    switch (level) {
      case 'CRITICAL': return 'CRITICAL';
      case 'HIGH': return 'SECURITY';
      case 'MEDIUM': return 'SECURITY';
      default: return 'INFO';
    }
  }

  /**
   * Get default anomaly result (safe fallback)
   */
  private getDefaultAnomalyResult(): AnomalyDetectionResult {
    return {
      isAnomalous: false,
      confidence: 0,
      anomalyType: 'BEHAVIORAL',
      severity: 'LOW',
      indicators: [],
      riskScore: 0,
      recommendation: 'ALLOW',
    };
  }

  /**
   * Get session statistics for a user
   */
  async getUserSessionStats(userId: string): Promise<{ totalSessions: number; activeSessions: number; riskScore: number }> {
    const sessions = Array.from(this.behavioralSessions.values()).filter(s => s.userId === userId);
    const activeSessions = sessions.filter(s => 
      Date.now() - s.lastRequest.getTime() <= this.config.sessionRetention
    );

    const avgRiskScore = sessions.length > 0 
      ? sessions.reduce((sum, s) => sum + s.riskScore, 0) / sessions.length 
      : 0;

    return {
      totalSessions: sessions.length,
      activeSessions: activeSessions.length,
      riskScore: avgRiskScore,
    };
  }

  /**
   * Get IP statistics
   */
  async getIPStats(ipAddress: string): Promise<{ sessionCount: number; avgRiskScore: number; isBlocked: boolean }> {
    const sessions = Array.from(this.behavioralSessions.values()).filter(s => s.ipAddress === ipAddress);
    const avgRiskScore = sessions.length > 0 
      ? sessions.reduce((sum, s) => sum + s.riskScore, 0) / sessions.length 
      : 0;

    const isBlocked = await this.ipReputation.isIPBlocked(ipAddress);

    return {
      sessionCount: sessions.length,
      avgRiskScore,
      isBlocked,
    };
  }
}