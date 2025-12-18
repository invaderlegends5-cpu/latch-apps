//src/device-fingerprinting/device-fingerprinting.service.ts
import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { EventLogService } from '../events/event.service';
import { SecurityMonitoringService } from '../security/security-monitor.service';
import { DeviceFingerprint, DeviceSessionPattern, DeviceReuseAlert, DeviceAnalysisResult } from './types/device.types';
import { EventType } from '../events/event.types';
import * as Sentry from '@sentry/node';

@Injectable()
export class DeviceFingerprintingService implements OnModuleInit {
  private readonly logger = new Logger(DeviceFingerprintingService.name);
  private readonly devicePatterns = new Map<string, DeviceSessionPattern>();
  private readonly recentDevices = new Map<string, Date[]>();

 private readonly config = {
    // Device fingerprinting configuration
    deviceUniquenessThreshold: 0.85, // If similarity > 85%, consider same device
    suspiciousRiskThreshold: 0.7, // Above this = suspicious
    newDeviceRiskThreshold: 0.3, // New devices have higher risk
    maxStoredFingerprints: 100, // Max fingerprints per user to store
    fingerprintRetentionDays: 90, // Days to retain device fingerprints
    
    // Feature weights for similarity calculation
    featureWeights: {
      userAgent: 0.3,
      os: 0.2,
      browser: 0.2,
      deviceType: 0.15,
      screenResolution: 0.1,
      timezone: 0.05,
    },

    rateLimiting: {
      maxRequestsPerMinute: 10, // Max device analysis requests per minute
      windowMs: 60 * 1000, // 1 minute window
    },

    // Bot detection configuration for device analysis
    // User Agent analysis
    knownBotPatterns: [
      'bot',
      'crawler', 
      'spider',
      'scraper',
      'harvester',
      'automated',
      'python-urllib',
      'java',
      'perl',
      'ruby',
      'node',
      'curl',
      'wget',
      'postman',
      'insomnia',
      'httpclient',
      'axios',
      'fetch',
      'playwright',
      'puppeteer',
      'selenium',
      'phantomjs',
      'googlebot',
      'bingbot',
      'slurp',
      'duckduckbot',
      'baiduspider',
      'yandexbot',
      'facebookexternalhit',
      'twitterbot',
      'linkedinbot',
    ],

    botDetection: {
      // Timing analysis
      minHumanInterval: 200, // Minimum ms between requests for human-like behavior
      maxBotInterval: 50, // Maximum ms between requests for bot-like behavior
      intervalEntropyThreshold: 0.3, // Below this = too predictable (bot-like)

      // Bot detection weights
      userAgentWeight: 0.3,
      timingWeight: 0.25,
      patternWeight: 0.25,
      sessionWeight: 0.2,

      // Risk score thresholds
      riskScoreThresholds: {
        low: 0.3,
        medium: 0.6,
        high: 0.8,
        critical: 0.95,
      },
    },
  };

  private checkRateLimit(ipAddress: string): boolean {
    const now = Date.now();
    const windowStart = now - this.config.rateLimiting.windowMs;
    
    const requests = this.recentDevices.get(ipAddress) || [];
    const validRequests = requests.filter(timestamp => timestamp.getTime() > windowStart);
    
    if (validRequests.length >= this.config.rateLimiting.maxRequestsPerMinute) {
      return false; // Rate limited
    }
    
    return true;
  }

  constructor(
    private readonly prisma: PrismaService,
    private readonly eventLog: EventLogService,
    private readonly securityMonitor: SecurityMonitoringService,
  ) {}

  async onModuleInit() {
    await this.initialize();
    this.logger.log('Device Fingerprinting Service initialized');
  }

  private async initialize() {
    // Load recent device patterns from database
    await this.loadRecentPatterns();
  }

  /**
   * Analyze device fingerprint for a new session/token
   */
  async analyzeDeviceFingerprint(
    userId: string,
    sessionId: string,
    userAgent: string | null,
    ipAddress: string | null,
  ): Promise<void> {
    try {
      // Validate inputs to prevent injection attacks
      if (!userId || typeof userId !== 'string') {
        throw new Error('Invalid user ID provided');
      }
      
      if (!sessionId || typeof sessionId !== 'string') {
        throw new Error('Invalid session ID provided');
      }
  
      // Rate limiting check
      if (ipAddress && !this.checkRateLimit(ipAddress)) {
        this.logger.warn(`Rate limit exceeded for IP: ${ipAddress}`);
        // Log security event for rate limiting
        await this.eventLog.logEvent('SECURITY_RATE_LIMIT', {
          userId,
          metadata: {
            reason: 'device_analysis_rate_limit',
            ipAddress,
          },
          ipAddress,
          userAgent,
          severity: 'SECURITY',
        });
        return; // Early return if rate limited
      }

      // Sanitize user agent and IP address
      const sanitizedUserAgent = this.sanitizeUserAgent(userAgent);
      const sanitizedIpAddress = this.sanitizeIpAddress(ipAddress);
  
      const fingerprint: DeviceFingerprint = {
        userAgent: sanitizedUserAgent,
        ipAddress: sanitizedIpAddress,
        ...this.parseUserAgent(sanitizedUserAgent),
      };
  
      // Check for device reuse patterns
      await this.checkDeviceReuse(userId, sessionId, fingerprint);
  
      // Update device pattern tracking
      await this.updateDevicePattern(userId, sessionId, fingerprint);
  
      // Log device fingerprint for audit trail
      await this.eventLog.logEvent('LOGIN', {
        userId,
        metadata: {
          sessionId,
          deviceFingerprint: {
            userAgent: fingerprint.userAgent,
            ipAddress: fingerprint.ipAddress,
            os: fingerprint.os,
            browser: fingerprint.browser,
            deviceType: fingerprint.deviceType,
          },
        },
        ipAddress: sanitizedIpAddress,
        userAgent: sanitizedUserAgent,
        severity: 'INFO',
      });
    } catch (error) {
      this.logger.error('Error analyzing device fingerprint:', error);
      Sentry.captureException(error);
    }
  }
  
  private sanitizeUserAgent(userAgent: string | null): string | null {
    if (!userAgent) return null;
    
    // Remove potentially dangerous characters, limit length
    return userAgent
      .substring(0, 1000) // Limit length to prevent abuse
      .replace(/[<>'"&]/g, ''); // Remove potential injection characters
  }
  
  private sanitizeIpAddress(ipAddress: string | null): string | null {
    if (!ipAddress) return null;
    
    // Basic IP address validation and sanitization
    const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:,\s*(?:[0-9]{1,3}\.){3}[0-9]{1,3})*$/;
    if (!ipRegex.test(ipAddress.trim())) {
      this.logger.warn(`Invalid IP address detected: ${ipAddress}`);
      return null;
    }
    
    return ipAddress.trim();
  }

  /**
   * Check for device reuse patterns (different devices using same account)
   */
  private async checkDeviceReuse(
    userId: string,
    currentSessionId: string,
    currentFingerprint: DeviceFingerprint,
  ): Promise<void> {
    try {
      // Get recent sessions for this user
      const recentSessions = await this.prisma.session.findMany({
        where: {
          userId,
          createdAt: { gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }, // Last 24 hours
          revoked: false,
        },
        include: {
          RefreshToken: true, // Keep this for production if you need it
        },
      });
  
      // Add null check and handle empty results gracefully
      if (!recentSessions || recentSessions.length === 0) {
        return;
      }
  
      // Check for different device patterns
      for (const session of recentSessions) {
        if (session.id === currentSessionId) continue; // Skip current session
  
        const sessionFingerprint = this.extractFingerprintFromSession(session);
  
        // Compare fingerprints for significant differences
        const isDifferentDevice = this.areFingerprintsDifferent(
          currentFingerprint,
          sessionFingerprint
        );
  
        if (isDifferentDevice) {
          await this.handleDeviceReuse(
            userId,
            currentSessionId,
            session.id,
            currentFingerprint,
            sessionFingerprint
          );
        }
      }
    } catch (error) {
      this.logger.error('Error in checkDeviceReuse:', error);
      Sentry.captureException(error);
      // Don't throw - this shouldn't break the main flow
      // In production, we want the authentication to continue even if device reuse checking fails
    }
  }

  /**
   * Handle detected device reuse
   */
  private async handleDeviceReuse(
    userId: string,
    currentSessionId: string,
    existingSessionId: string,
    currentFingerprint: DeviceFingerprint,
    existingFingerprint: DeviceFingerprint,
  ): Promise<void> {
    // Determine severity based on fingerprint differences
    const severity = this.calculateReuseSeverity(currentFingerprint, existingFingerprint);
    
    const alert: DeviceReuseAlert = {
      id: `device-reuse-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      userId,
      primaryFingerprint: currentFingerprint,
      secondaryFingerprint: existingFingerprint,
      primarySessionId: currentSessionId,
      secondarySessionId: existingSessionId,
      timestamp: new Date(),
      severity,
      reason: this.getReuseReason(currentFingerprint, existingFingerprint),
    };

    // Log the device reuse event
    await this.eventLog.logEvent('TOKEN_REUSE', {
      userId,
      metadata: {
        reason: 'device_reuse_detected',
        primarySessionId: currentSessionId,
        secondarySessionId: existingSessionId,
        primaryFingerprint: currentFingerprint,
        secondaryFingerprint: existingFingerprint,
        severity,
      },
      ipAddress: currentFingerprint.ipAddress,
      userAgent: currentFingerprint.userAgent,
      severity: this.mapSeverityToEvent(alert.severity),
    });

    // Trigger security alert
    await this.securityMonitor['handleEvent']({
      id: alert.id,
      type: 'TOKEN_REUSE' as EventType,
      severity: this.mapSeverityToEvent(alert.severity),
      userId,
      tenantId: null,
      ipAddress: currentFingerprint.ipAddress,
      userAgent: currentFingerprint.userAgent,
      sessionId: currentSessionId,
      familyId: null,
      reason: 'device_reuse_detected',
      integrityHash: '',
      prevHash: null,
      metadata: {
        primarySessionId: currentSessionId,
        secondarySessionId: existingSessionId,
        primaryFingerprint: currentFingerprint,
        secondaryFingerprint: existingFingerprint,
        severity,
      },
      createdAt: new Date(),
    });

    this.logger.warn(`Device reuse detected for user ${userId}:`, alert);
  }

  /**
   * Update device pattern tracking
   */
  private async updateDevicePattern(
    userId: string,
    sessionId: string,
    fingerprint: DeviceFingerprint,
  ): Promise<void> {
    const patternKey = this.getDevicePatternKey(userId, fingerprint);
    
    let pattern = this.devicePatterns.get(patternKey);
    if (!pattern) {
      pattern = {
        userId,
        fingerprint,
        sessionIds: [sessionId],
        tokenFamilyIds: [],
        firstSeen: new Date(),
        lastSeen: new Date(),
        active: true,
      };
    } else {
      if (!pattern.sessionIds.includes(sessionId)) {
        pattern.sessionIds.push(sessionId);
      }
      pattern.lastSeen = new Date();
    }

    this.devicePatterns.set(patternKey, pattern);

    // Track recent device usage for rate limiting
    const deviceKey = `${userId}:${fingerprint.ipAddress || 'unknown'}:${fingerprint.userAgent || 'unknown'}`;
    const timestamps = this.recentDevices.get(deviceKey) || [];
    timestamps.push(new Date());
    
    // Keep only recent timestamps within the window
    const windowStart = Date.now() - this.config.rateLimiting.windowMs;
    const validTimestamps = timestamps.filter(timestamp => timestamp.getTime() > windowStart);
    
    this.recentDevices.set(deviceKey, validTimestamps);
  }

  /**
   * Load recent patterns from database
   */
  private async loadRecentPatterns(): Promise<void> {
    try {
      // Load recent sessions with device info for pattern analysis
      const recentSessions = await this.prisma.session.findMany({
        where: {
          createdAt: { gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }, // Last 7 days
        },
        take: 1000,
      });

      for (const session of recentSessions) {
        if (session.userAgent || session.ipAddress) {
          const fingerprint: DeviceFingerprint = {
            userAgent: session.userAgent,
            ipAddress: session.ipAddress,
            ...this.parseUserAgent(session.userAgent),
          };
          
          await this.updateDevicePattern(session.userId, session.id, fingerprint);
        }
      }
    } catch (error) {
      this.logger.error('Error loading recent patterns:', error);
    }
  }

  /**
   * Parse user agent string to extract device info
   */
  private parseUserAgent(userAgent: string | null): Partial<DeviceFingerprint> {
    if (!userAgent) return {};

    const result: Partial<DeviceFingerprint> = {};
    const lowerUserAgent = userAgent.toLowerCase(); // Convert to lowercase for comparisons

    // Detect OS - case-insensitive
    if (lowerUserAgent.includes('windows')) result.os = 'Windows';
    else if (lowerUserAgent.includes('iphone') || lowerUserAgent.includes('ipad')) result.os = 'iOS';
    else if (lowerUserAgent.includes('mac os x')) result.os = 'macOS';
    else if (lowerUserAgent.includes('android')) result.os = 'Android';
    else if (lowerUserAgent.includes('linux')) result.os = 'Linux';
  
    // Detect browser - case-insensitive
    if (lowerUserAgent.includes('chrome') && !lowerUserAgent.includes('edg') && !lowerUserAgent.includes('opr/')) {
      result.browser = 'Chrome';
    } 
    else if (lowerUserAgent.includes('edg')) {
      result.browser = 'Edge';
    } 
    else if (lowerUserAgent.includes('firefox')) {
      result.browser = 'Firefox';
    } 
    else if (lowerUserAgent.includes('safari') && !lowerUserAgent.includes('chrome')) {
      result.browser = 'Safari';
    } 
    else if (lowerUserAgent.includes('opera') || lowerUserAgent.includes('opr/')) {
      result.browser = 'Opera';
    }
  // Additional fallback for common browsers that might be detected by other identifiers
  else if (lowerUserAgent.includes('Gecko')) {
    // This is likely Firefox, even if it doesn't explicitly say Firefox
    result.browser = 'Firefox';
  }


    // Detect device type with better accuracy
    const mobileRegex = /(Mobile|Android|iPhone|iPod|BlackBerry|IEMobile|Opera Mini)/i;
    const tabletRegex = /(iPad|Android(?!.*Mobile)|Tablet|PlayBook)/i;
    
    if (tabletRegex.test(userAgent)) {
      result.deviceType = 'tablet';
    } else if (mobileRegex.test(userAgent)) {
      result.deviceType = 'mobile';
    } else {
      result.deviceType = 'desktop';
    }

    return result;
  }

  /**
   * Extract fingerprint from session data
   */
  private extractFingerprintFromSession(session: any): DeviceFingerprint {
    return {
      userAgent: session.userAgent,
      ipAddress: session.ipAddress,
      ...this.parseUserAgent(session.userAgent),
    };
  }

  /**
   * Compare two device fingerprints for differences
   */
  private areFingerprintsDifferent(
    fp1: DeviceFingerprint,
    fp2: DeviceFingerprint,
  ): boolean {
    // Different IP addresses = different devices
    if (fp1.ipAddress && fp2.ipAddress && fp1.ipAddress !== fp2.ipAddress) {
      return true;
    }

    // Different user agents with different OS = different devices
    if (fp1.os && fp2.os && fp1.os !== fp2.os) {
      return true;
    }

    // Different browsers on same OS might be different devices
    if (fp1.browser && fp2.browser && fp1.browser !== fp2.browser && fp1.os === fp2.os) {
      return true;
    }

    // Mobile vs desktop on same account = potential reuse
    if (fp1.deviceType && fp2.deviceType && fp1.deviceType !== fp2.deviceType) {
      return true;
    }

    return false;
  }

  /**
   * Calculate reuse severity based on fingerprint differences
   */
  private calculateReuseSeverity(
    fp1: DeviceFingerprint,
    fp2: DeviceFingerprint,
  ): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
    const differences: string[] = [];
    
    if (fp1.ipAddress !== fp2.ipAddress) differences.push('IP');
    if (fp1.os !== fp2.os) differences.push('OS');
    if (fp1.browser !== fp2.browser) differences.push('BROWSER');
    if (fp1.deviceType !== fp2.deviceType) differences.push('DEVICE_TYPE');

    const diffCount = differences.length;
    if (diffCount >= 3) return 'CRITICAL';
    if (diffCount === 2) return 'HIGH';
    if (diffCount === 1) return 'MEDIUM';
    return 'LOW';
  }

  /**
   * Get reuse reason
   */
  private getReuseReason(fp1: DeviceFingerprint, fp2: DeviceFingerprint): string {
    const reasons: string[] = [];
    
    if (fp1.ipAddress !== fp2.ipAddress) reasons.push('different IP addresses');
    if (fp1.os !== fp2.os) reasons.push('different operating systems');
    if (fp1.browser !== fp2.browser) reasons.push('different browsers');
    if (fp1.deviceType !== fp2.deviceType) reasons.push('different device types');

    return reasons.length > 0 ? reasons.join(' and ') : 'unknown device difference';
  }

  /**
   * Get device pattern key for tracking
   */
  private getDevicePatternKey(userId: string, fingerprint: DeviceFingerprint): string {
    return `${userId}:${fingerprint.ipAddress || 'unknown'}:${fingerprint.userAgent || 'unknown'}`;
  }

  /**
   * Map severity to event severity
   */
  private mapSeverityToEvent(severity: string): 'INFO' | 'SECURITY' | 'CRITICAL' | 'ERROR' {
    switch (severity) {
      case 'CRITICAL': return 'CRITICAL';
      case 'HIGH': return 'SECURITY';
      case 'MEDIUM': return 'SECURITY';
      default: return 'INFO';
    }
  }

  /**
   * Get device reuse statistics for a user
   */
  async getDeviceReuseStats(userId: string): Promise<any> {
    const patterns = Array.from(this.devicePatterns.values())
      .filter(p => p.userId === userId);

    return {
      totalDevices: patterns.length,
      activeDevices: patterns.filter(p => p.active).length,
      devicePatterns: patterns.map(p => ({
        fingerprint: p.fingerprint,
        sessionCount: p.sessionIds.length,
        firstSeen: p.firstSeen,
        lastSeen: p.lastSeen,
      })),
    };
  }

 /**
   * NEW: Analyze device fingerprint for bot-like behavior
   */
 async analyzeDeviceForBot(
  userId: string | null,
  sessionId: string | null,
  userAgent: string | null,
  ipAddress: string | null,
  method: string = 'GET',
  url: string = '/',
  responseTime: number = 0,
): Promise<DeviceAnalysisResult> {
  try {
    const fingerprint: DeviceFingerprint = {
      userAgent,
      ipAddress,
      ...this.parseUserAgent(userAgent),
    };

    // Perform device-specific bot analysis
    const userAgentAnalysis = this.analyzeUserAgentForBot(userAgent);
    const timingAnalysis = this.analyzeTimingForBot(responseTime);
    const patternAnalysis = this.analyzePatternForBot(method, url);
    const sessionAnalysis = await this.analyzeSessionForBot(sessionId);

    // Calculate risk score
    const riskScore = this.calculateDeviceRiskScore(
      userAgentAnalysis.confidence,
      timingAnalysis.confidence,
      patternAnalysis.confidence,
      sessionAnalysis.confidence
    );

    // Determine bot status
    const isBot = riskScore > this.config.suspiciousRiskThreshold || userAgentAnalysis.confidence >= 0.7;
    const confidence = Math.max(riskScore, userAgentAnalysis.confidence);

    // Compile indicators
    const indicators = [
      ...userAgentAnalysis.isBot ? [userAgentAnalysis.indicator] : [],
      ...timingAnalysis.isBot ? [timingAnalysis.indicator] : [],
      ...patternAnalysis.isBot ? [patternAnalysis.indicator] : [],
      ...sessionAnalysis.isBot ? [sessionAnalysis.indicator] : [],
    ];

     // Determine recommendation based on risk score
let recommendation: 'BLOCK' | 'CHALLENGE' | 'ALLOW' = riskScore > this.config.botDetection.riskScoreThresholds.critical ? 'BLOCK' :
riskScore > this.config.botDetection.riskScoreThresholds.high ? 'CHALLENGE' : 'ALLOW';

// For high confidence bot signatures, override recommendation
if (userAgentAnalysis.confidence > 0.8) {
recommendation = 'BLOCK';
}


    // Log device bot analysis
    if (isBot) {
      await this.eventLog.logEvent('SECURITY_CSRF_ERROR', {
        userId: userId,
        tenantId: null,
        metadata: {
          analysisType: 'DEVICE_BOT_DETECTION',
          riskScore,
          confidence,
          isBot,
          recommendation,
          indicators,
          userAgentAnalysis: userAgentAnalysis.isBot,
          timingAnalysis: timingAnalysis.isBot,
          patternAnalysis: patternAnalysis.isBot,
          sessionAnalysis: sessionAnalysis.isBot,
        },
        ipAddress,
        userAgent,
        severity: this.mapRiskScoreToEventSeverity(riskScore),
      });
    }

    return {
      deviceId: this.generateDeviceId(fingerprint),
      isBot,
      confidence,
      riskScore,
      isSuspicious: isBot,
      indicators,
      recommendation,
      similarityScore: 0, // Would need to compare with historical data
      matchedDevices: [], // Would need to compare with historical data
      isNewDevice: true, // Would need to check against historical data
      analysis: {
        userAgent: userAgentAnalysis.isBot,
        deviceType: userAgentAnalysis.isBot, // Device type analysis is part of user agent
        browser: userAgentAnalysis.isBot,   // Browser analysis is part of user agent
        os: userAgentAnalysis.isBot,        // OS analysis is part of user agent
        timing: timingAnalysis.isBot,
        pattern: patternAnalysis.isBot,
      },
      firstSeen: new Date(),
      lastSeen: new Date(),
    };
  } catch (error) {
    this.logger.error('Error in device bot analysis:', error);
    Sentry.captureException(error);
    
    // Return safe default
    return {
      deviceId: 'unknown',
      isBot: false,
      confidence: 0,
      riskScore: 0,
      isSuspicious: false,
      indicators: ['ANALYSIS_ERROR'],
      recommendation: 'ALLOW',
      similarityScore: 0,
      matchedDevices: [],
      isNewDevice: true,
      analysis: {
        userAgent: false,
        deviceType: false,
        browser: false,
        os: false,
        timing: false,
        pattern: false,
      },
      firstSeen: new Date(),
      lastSeen: new Date(),
    };
  }
}

/**
 *  Analyze user agent for bot signatures
 */
private analyzeUserAgentForBot(userAgent: string | null): { isBot: boolean; confidence: number; indicator: string } {
  if (!userAgent) {
    return { isBot: false, confidence: 0, indicator: 'No user agent' };
  }

  const lowerUserAgent = userAgent.toLowerCase();

  // Check for non-browser clients FIRST (more specific category)
  const nonBrowserPatterns = [
    'python',
    'java',
    'curl',
    'wget',
    'postman',
    'insomnia',
    'httpclient',
    'axios',
    'fetch',
    'playwright',
    'puppeteer',
    'selenium',
    'phantomjs',
    'headless',
  ];

  const nonBrowserMatch = nonBrowserPatterns.some(pattern => 
    lowerUserAgent.includes(pattern)
  );

  if (nonBrowserMatch) {
    return { 
      isBot: true, 
      confidence: 0.7, 
      indicator: `Non-browser client: ${userAgent}` 
    };
  }

  // Then check for known bot signatures (more general category)
  const knownBot = this.config.knownBotPatterns.some(bot => 
    lowerUserAgent.includes(bot.toLowerCase())
  );

  if (knownBot) {
    return { 
      isBot: true, 
      confidence: 0.9, 
      indicator: `Known bot signature: ${userAgent}` 
    };
  }

  // Minimal user agents often indicate bots
  if (userAgent.length < 20) {
    return { 
      isBot: true, 
      confidence: 0.7, 
      indicator: `Minimal user agent: ${userAgent.length} chars` 
    };
  }

  return { isBot: false, confidence: 0, indicator: 'Normal user agent' };
}

/**
 * NEW: Analyze timing for bot-like patterns
 */
private analyzeTimingForBot(responseTime: number): { isBot: boolean; confidence: number; indicator: string } {
  if (responseTime === 0) {
    return { isBot: false, confidence: 0, indicator: 'No timing data' };
  }

  // Extremely fast response times (less than 10ms) often indicate automation
  if (responseTime < 10) {
    return { 
      isBot: true, 
      confidence: 0.6, 
      indicator: `Very fast response: ${responseTime}ms` 
    };
  }

  // Very slow response times might also indicate bot processing
  if (responseTime > 5000) {
    return { 
      isBot: true, 
      confidence: 0.4, 
      indicator: `Very slow response: ${responseTime}ms` 
    };
  }

  return { isBot: false, confidence: 0, indicator: 'Normal response time' };
}

/**
 * NEW: Analyze request patterns for bot behavior
 */
private analyzePatternForBot(method: string, url: string): { isBot: boolean; confidence: number; indicator: string } {
  // Suspicious URL patterns
  const suspiciousUrls = [
    '/admin',
    '/wp-admin',
    '/phpmyadmin',
    '/backup',
    '/config',
    '/private',
    '/api/graphql',
    '/graphql',
    '/api/v1',
    '/api/v2',
    '/api/v3',
  ];

  const isSuspiciousUrl = suspiciousUrls.some(pattern => 
    url.toLowerCase().includes(pattern.toLowerCase())
  );

  if (isSuspiciousUrl) {
    return { 
      isBot: true, 
      confidence: 0.4, 
      indicator: `Suspicious URL: ${url}` 
    };
  }

  // Suspicious HTTP methods
  const suspiciousMethods = ['TRACE', 'CONNECT', 'OPTIONS'];
  if (suspiciousMethods.includes(method.toUpperCase())) {
    return { 
      isBot: true, 
      confidence: 0.5, 
      indicator: `Suspicious method: ${method}` 
    };
  }

  return { isBot: false, confidence: 0, indicator: 'Normal pattern' };
}

/**
 * NEW: Analyze session for bot-like behavior
 */
private async analyzeSessionForBot(sessionId: string | null): Promise<{ isBot: boolean; confidence: number; indicator: string }> {
  if (!sessionId) {
    return { isBot: false, confidence: 0, indicator: 'No session' };
  }

  try {
    const session = await this.prisma.session.findUnique({
      where: { id: sessionId },
    });

    if (!session) {
      return { isBot: false, confidence: 0, indicator: 'Session not found' };
    }

    // Check for suspicious session characteristics
    // This would be enhanced with more sophisticated analysis
    
    return { isBot: false, confidence: 0, indicator: 'Normal session' };
  } catch (error) {
    this.logger.error('Error analyzing session for bot detection:', error);
    return { isBot: false, confidence: 0, indicator: 'Session analysis error' };
  }
}

/**
 * NEW: Calculate device risk score
 */
private calculateDeviceRiskScore(
  userAgentConfidence: number,
  timingConfidence: number,
  patternConfidence: number,
  sessionConfidence: number,
): number {
  // Use the same weights as in bot detection for consistency
  const totalWeight = this.config.botDetection.userAgentWeight + 
                     this.config.botDetection.timingWeight + 
                     this.config.botDetection.patternWeight + 
                     this.config.botDetection.sessionWeight;
  
  const weightedScore = 
    (userAgentConfidence * this.config.botDetection.userAgentWeight) +
    (timingConfidence * this.config.botDetection.timingWeight) +
    (patternConfidence * this.config.botDetection.patternWeight) +
    (sessionConfidence * this.config.botDetection.sessionWeight);

  return weightedScore / totalWeight;
}

/**
 * NEW: Map risk score to event severity
 */
private mapRiskScoreToEventSeverity(score: number): 'INFO' | 'SECURITY' | 'CRITICAL' | 'ERROR' {
  if (score >= 0.9) return 'CRITICAL';
  if (score >= 0.7) return 'SECURITY';
  if (score >= 0.5) return 'SECURITY';
  return 'INFO';
}

/**
 * NEW: Generate device ID for tracking
 */
private generateDeviceId(fingerprint: DeviceFingerprint): string {
  const fingerprintString = JSON.stringify({
    userAgent: fingerprint.userAgent,
    ipAddress: fingerprint.ipAddress,
    os: fingerprint.os,
    browser: fingerprint.browser,
    deviceType: fingerprint.deviceType,
  });

  // Simple hash function
  let hash = 0;
  for (let i = 0; i < fingerprintString.length; i++) {
    const char = fingerprintString.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32bit integer
  }
  
  return `device-${Math.abs(hash).toString(36)}`;
}

}