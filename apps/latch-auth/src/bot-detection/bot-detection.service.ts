import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';
import { EventLogService } from '../events/event.service';
import { BehavioralAnalysisService } from '../behavioral-analysis/behavioral-analysis.service';
import { RedisService } from '../redis/redis.service';
import { IPReputationService } from '../ip-reputation/ip-reputation.service';
import { RequestPattern } from '../behavioral-analysis/types/behavior.types';
import * as Sentry from '@sentry/node';
import { DeviceFingerprintingService } from '@/device-fingerprinting/device-fingerprinting.service';

export interface BotDetectionResult {
  isBot: boolean;
  confidence: number; // 0-1
  indicators: string[];
  riskScore: number;
  recommendation: 'ALLOW' | 'CHALLENGE' | 'BLOCK';
  analysis: {
    userAgent: boolean;
    timing: boolean;
    navigation: boolean;
    requestPattern: boolean;
    sessionBehavior: boolean;
    deviceFingerprint: boolean;
  };
}

@Injectable()
export class BotDetectionService implements OnModuleInit {
  private readonly logger = new Logger(BotDetectionService.name);
  private config = {
    // User Agent analysis
    knownBotUserAgents: [
      'googlebot',
      'bingbot',
      'slurp',
      'duckduckbot',
      'baiduspider',
      'yandexbot',
      'facebookexternalhit',
      'twitterbot',
      'linkedinbot',
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
      'headless',
    ],
    
    // Timing analysis thresholds
    minHumanInterval: 200, // Minimum ms between requests for human-like behavior
    maxBotInterval: 50, // Maximum ms between requests for bot-like behavior
    intervalEntropyThreshold: 0.3, // Below this = too predictable (bot-like)
    
    // Risk scoring weights
    userAgentWeight: 0.25,
    timingWeight: 0.2,
    patternWeight: 0.2,
    sessionWeight: 0.15,
    deviceWeight: 0.2,
    
    // Behavioral thresholds
    riskScoreThresholds: {
      low: 0.3,
      medium: 0.6,
      high: 0.8,
      critical: 0.95,
    },

  // IP blocking configuration
  autoBlockThreshold: 0.9, // Auto-block when risk score exceeds this
  autoBlockDuration: 60 * 60 * 1000, // 1 hour in milliseconds
  maxAutoBlockDuration: 7 * 24 * 60 * 60 * 1000, // 7 days maximum
};  

  constructor(
    private readonly prisma: PrismaService,
    private readonly eventLog: EventLogService,
    private readonly behavioralAnalysis: BehavioralAnalysisService,
    private readonly redis: RedisService,
    private readonly ipReputation: IPReputationService,
    private readonly configService: ConfigService,
    private readonly deviceFingerprinting: DeviceFingerprintingService,
  ) {}

  async onModuleInit() {
    this.synchronizeConfiguration();
    await this.initialize();
    this.logger.log('Bot Detection Service initialized');
  }

  private synchronizeConfiguration() {
    const uaList = this.configService.get<string[]>('botDetection.knownBotUserAgents');
    // Only update the config list if the retrieved list exists and is non-empty
    if (uaList && Array.isArray(uaList) && uaList.length > 0) {
      this.logger.log('Overriding default bot user agent list with configuration.');
      this.config.knownBotUserAgents = uaList;
    } else {
      // Optional: Log that defaults are being used
      this.logger.log('Using default bot user agent list.');
    }

    const thresholds = this.configService.get('botDetection.riskScoreThresholds');
    if (thresholds) {
      Object.assign(this.config.riskScoreThresholds, thresholds);
    }

    // You would add similar logic for timing, weights, autoBlockThreshold, etc.

 // Example for autoBlockThreshold if it were also configurable:
 const autoBlockThreshold = this.configService.get<number>('botDetection.autoBlockThreshold');
 if (typeof autoBlockThreshold === 'number') {
     this.config.autoBlockThreshold = autoBlockThreshold;
     this.logger.log('Updated auto-block threshold with configuration.', { autoBlockThreshold });
 }

    // Example for weights if they were also configurable:
    // const weights = this.configService.get('botDetection.weights');
    // if (weights) {
    //   Object.assign(this.config, { userAgentWeight, timingWeight, ...weights });
    // }
  }

  private async initialize() {
    // Load any initial configuration or cached data
    await this.loadBotPatterns();
  }

  /**
   * Analyze a request for bot-like behavior
   */
  async analyzeRequest(
    userId: string | null,
    sessionId: string | null,
    ipAddress: string | null,
    userAgent: string | null,
    method: string,
    url: string,
    responseTime: number = 0,
  ): Promise<BotDetectionResult> {
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

      // Perform comprehensive bot detection analysis
      const userAgentAnalysis = this.analyzeUserAgent(userAgent);
      const timingAnalysis = this.analyzeTimingPattern(requestPattern);
      const patternAnalysis = this.analyzeRequestPattern(requestPattern);
      const sessionAnalysis = await this.analyzeSessionBehavior(sessionId);

//  Add device fingerprint analysis
const deviceAnalysis = await this.analyzeDeviceFingerprint(
    userId,
    sessionId,
    userAgent,
    ipAddress,
    method,
    url,
    responseTime
  );

      // Calculate overall risk score
      const riskScore = this.calculateRiskScore(
        userAgentAnalysis.confidence,
        timingAnalysis.confidence,
        patternAnalysis.confidence,
        sessionAnalysis.confidence,
        deviceAnalysis.confidence 
      );

      // Determine bot status
      const isBot = riskScore > this.config.riskScoreThresholds.medium || userAgentAnalysis.isBot;
      
      const confidence = Math.max(
        riskScore,
        userAgentAnalysis.confidence,
        timingAnalysis.confidence,
        patternAnalysis.confidence,
        sessionAnalysis.confidence,
        deviceAnalysis.confidence
      );
      
      // Compile indicators
      const indicators = [
        ...userAgentAnalysis.isBot ? [userAgentAnalysis.indicator] : [],
        ...timingAnalysis.isBot ? [timingAnalysis.indicator] : [],
        ...patternAnalysis.isBot ? [patternAnalysis.indicator] : [],
        ...sessionAnalysis.isBot ? [sessionAnalysis.indicator] : [],
        ...deviceAnalysis.isBot ? [deviceAnalysis.indicator] : [],
      ];

      // AUTO-BLOCK HIGH-RISK IPS
// NEW LOGIC: Block if the calculated risk score is high, OR if any single analysis component has very high confidence
const shouldAutoBlock = riskScore > this.config.autoBlockThreshold ||
userAgentAnalysis.confidence > 0.94 || 
timingAnalysis.confidence > 0.94 ||
patternAnalysis.confidence > 0.94 ||
sessionAnalysis.confidence > 0.94 ||
deviceAnalysis.confidence > 0.94; 

if (ipAddress && shouldAutoBlock) { // Use the new condition
await this.handleHighRiskIP(ipAddress, riskScore, indicators);
}

      // Determine recommendation
      // NEW LOGIC: Recommend BLOCK if calculated score is high, OR if any single analysis component has very high confidence
      const shouldRecommendBlock = riskScore > this.config.riskScoreThresholds.critical ||
                                  userAgentAnalysis.confidence > 0.94 ||
                                  timingAnalysis.confidence > 0.94 ||
                                  patternAnalysis.confidence > 0.94 ||
                                  sessionAnalysis.confidence > 0.94 ||
                                  deviceAnalysis.confidence > 0.94; 

      // NEW LOGIC: Recommend CHALLENGE if calculated score is high OR any single component is moderately high
// (e.g., > 0.7), but only if it's not already recommended for BLOCKING.
const shouldRecommendChallenge = !shouldRecommendBlock && ( // Only check for CHALLENGE if not already BLOCK
  riskScore > this.config.riskScoreThresholds.high ||
  userAgentAnalysis.confidence >= 0.7 || // <-- Threshold for CHALLENGE, lower than BLOCK threshold
  timingAnalysis.confidence >= 0.7 ||
  patternAnalysis.confidence >= 0.7 ||
  sessionAnalysis.confidence >= 0.7 ||
  deviceAnalysis.confidence >= 0.7  // <-- e.g., deviceAnalysis.confidence (0.7) IS > 0.7 (barely)
);
      
const recommendation = shouldRecommendBlock ? 'BLOCK' :
shouldRecommendChallenge ? 'CHALLENGE' : 'ALLOW';

      // Note: The old auto-block logic below is now redundant due to the shouldAutoBlock check above.
      // It can be removed.
      // if (ipAddress && riskScore > this.config.autoBlockThreshold) {
      //    await this.handleHighRiskIP(ipAddress, riskScore, indicators);
      //  }

      // Log bot detection analysis
      if (isBot) {
        await this.eventLog.logEvent('SECURITY_CSRF_ERROR', {
          userId: userId,
          tenantId: null, // Could be enhanced with tenant context
          metadata: {
            analysisType: 'BOT_DETECTION',
            riskScore,
            confidence,
            isBot,
            recommendation,
            indicators,
            userAgentAnalysis: userAgentAnalysis.isBot,
            timingAnalysis: timingAnalysis.isBot,
            patternAnalysis: patternAnalysis.isBot,
            sessionAnalysis: sessionAnalysis.isBot,
            deviceAnalysis: deviceAnalysis.isBot,
            deviceFingerprint: deviceAnalysis.isBot,
          },
          ipAddress,
          userAgent,
          severity: this.mapRiskScoreToEventSeverity(riskScore),
        });
      }

      return {
        isBot,
        confidence,
        indicators,
        riskScore,
        recommendation,
        analysis: {
          userAgent: userAgentAnalysis.isBot,
          timing: timingAnalysis.isBot,
          navigation: patternAnalysis.isBot,
          requestPattern: patternAnalysis.isBot,
          sessionBehavior: sessionAnalysis.isBot,
          deviceFingerprint: deviceAnalysis.isBot,
        },
      };
    } catch (error) {
      this.logger.error('Error in bot detection:', error);
      Sentry.captureException(error);
      return this.getDefaultBotDetectionResult();
    }
  }

  /**
   * Handle high-risk IP by adding to block list
   */
  private async handleHighRiskIP(ipAddress: string, riskScore: number, indicators: string[]): Promise<void> {
    try {
      // Check if IP is already blocked
      const isBlocked = await this.ipReputation.isIPBlocked(ipAddress);
      if (isBlocked) {
        // IP already blocked, just log the continued suspicious activity
        await this.eventLog.logEvent('SECURITY_CSRF_ERROR', {
          userId: null,
          tenantId: null,
          metadata: {
            reason: 'continued_bot_activity_on_blocked_ip',
            ipAddress,
            riskScore,
            indicators,
          },
          ipAddress,
          userAgent: null,
          severity: 'CRITICAL',
        });
        return;
      }

      // Block the IP
      const reason = `High bot risk detected: ${indicators.join(', ')}`;
      await this.ipReputation.blockIP(
        ipAddress,
        reason,
        this.config.autoBlockDuration
      );

      // Log the blocking action
      await this.eventLog.logEvent('SECURITY_CSRF_ERROR', {
        userId: null,
        tenantId: null,
        metadata: {
          reason: 'auto_block_high_risk_bot_ip',
          ipAddress,
          riskScore,
          indicators,
          blockReason: reason,
          blockDuration: this.config.autoBlockDuration,
        },
        ipAddress,
        userAgent: null,
        severity: 'CRITICAL',
      });

      this.logger.warn(`Auto-blocked IP ${ipAddress} due to high bot risk score: ${riskScore}`);
    } catch (error) {
      this.logger.error(`Failed to auto-block high-risk IP ${ipAddress}:`, error);
      Sentry.captureException(error);
      throw error;
    }
  }

  /**
   * Analyze user agent for bot signatures
   */
  private analyzeUserAgent(userAgent: string | null): { isBot: boolean; confidence: number; indicator: string } {
    if (!userAgent) {
      return { isBot: false, confidence: 0, indicator: 'No user agent' };
    }

    const lowerUserAgent = userAgent.toLowerCase();
    
    // Check for known bot signatures
    const knownBot = this.config.knownBotUserAgents.some(bot => 
      lowerUserAgent.includes(bot.toLowerCase())
    );

    if (knownBot) {
      console.log(`DEBUG analyzeUserAgent: Matched knownBotUserAgents pattern. UA: "${userAgent}", Matched pattern (example): "${this.config.knownBotUserAgents.find(bot => lowerUserAgent.includes(bot.toLowerCase()))}"`);
    }

    if (knownBot) {
      return { 
        isBot: true, 
        confidence: 0.9, 
        indicator: `Known bot user agent pattern detected: ${userAgent}` 
      };
    }

    // Check for non-browser patterns
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
      console.log(`DEBUG analyzeUserAgent: Matched nonBrowserPatterns. UA: "${userAgent}", Matched pattern (example): "${nonBrowserPatterns.find(pattern => lowerUserAgent.includes(pattern))}"`);
    }

    if (nonBrowserMatch) {
      return { 
        isBot: true, 
        confidence: 0.7, 
        indicator: `Non-browser client detected: ${userAgent}` 
      };
    }

    // Check for minimal user agents (often bots)
    if (userAgent.length < 20) {
      return { 
        isBot: true, 
        confidence: 0.5, 
        indicator: `Minimal user agent length: ${userAgent.length} chars` 
      };
    }

    return { isBot: false, confidence: 0, indicator: 'Human-like user agent' };
  }

  /**
   * Analyze timing patterns for bot-like behavior
   */
  private analyzeTimingPattern(request: RequestPattern): { isBot: boolean; confidence: number; indicator: string } {
    // This would analyze timing patterns against historical data
    // For now, we'll return a basic analysis
    // In a real implementation, this would check request intervals, timing entropy, etc.
    
    // If this is the first request, we can't analyze timing
    if (!request.sessionId) {
      return { isBot: false, confidence: 0, indicator: 'First request - no timing data' };
    }

    // Basic check for very rapid requests
    if (request.responseTime < 10) { // Very fast response times can indicate automation
      return { 
        isBot: true, 
        confidence: 0.6, 
        indicator: `Unusually fast response time: ${request.responseTime}ms` 
      };
    }

    return { isBot: false, confidence: 0, indicator: 'Normal timing pattern' };
  }

  /**
   * Analyze request patterns for bot-like behavior
   */
  private analyzeRequestPattern(request: RequestPattern): { isBot: boolean; confidence: number; indicator: string } {
    // Analyze URL patterns that bots commonly follow
    const botUrlPatterns = [
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

    const isBotUrl = botUrlPatterns.some(pattern => 
      request.url.toLowerCase().includes(pattern.toLowerCase())
    );

    if (isBotUrl) {
      return { 
        isBot: true, 
        confidence: 0.4, 
        indicator: `Suspicious URL pattern accessed: ${request.url}` 
      };
    }

    // Analyze request method patterns
    const suspiciousMethods = ['TRACE', 'CONNECT', 'OPTIONS'];
    if (suspiciousMethods.includes(request.method.toUpperCase())) {
      return { 
        isBot: true, 
        confidence: 0.5, 
        indicator: `Suspicious HTTP method: ${request.method}` 
      };
    }

    return { isBot: false, confidence: 0, indicator: 'Normal request pattern' };
  }

  /**
   * Analyze session behavior for bot-like patterns
   */
  private async analyzeSessionBehavior(sessionId: string | null): Promise<{ isBot: boolean; confidence: number; indicator: string }> {
    if (!sessionId) {
      return { isBot: false, confidence: 0, indicator: 'No session context' };
    }

    try {
      // Get session data to analyze behavior
      const session = await this.prisma.session.findUnique({
        where: { id: sessionId },
      });

      if (!session) {
        return { isBot: false, confidence: 0, indicator: 'Session not found' };
      }

      // Check for suspicious session characteristics
      if (session.ipAddress && session.userAgent) {
        // This could be enhanced with more sophisticated session analysis
        // For now, we'll return a basic result
        
        // Check if IP has been flagged by IP reputation system
        // This would require integration with IPReputationService
        return { isBot: false, confidence: 0, indicator: 'Normal session behavior' };
      }

      return { isBot: false, confidence: 0, indicator: 'Normal session behavior' };
    } catch (error) {
      this.logger.error('Error analyzing session behavior:', error);
      return { isBot: false, confidence: 0, indicator: 'Session analysis error' };
    }
  }

/**
 *  Analyze device fingerprint for bot-like behavior
 */
private async analyzeDeviceFingerprint(
    userId: string | null,
    sessionId: string | null,
    userAgent: string | null,
    ipAddress: string | null,
    method: string,
    url: string,
    responseTime: number,
  ): Promise<{ isBot: boolean; confidence: number; indicator: string }> {
    if (!userAgent || !ipAddress) {
      return { isBot: false, confidence: 0, indicator: 'Missing device data' };
    }
  
    // Use the device fingerprinting service for bot analysis
    try {
      const deviceResult = await this.deviceFingerprinting.analyzeDeviceForBot(
        userId,
        sessionId,
        userAgent,
        ipAddress,
        method,
        url,
        responseTime
      );
  
      return {
        isBot: deviceResult.isBot,
        confidence: deviceResult.confidence,
        indicator: `Device fingerprint analysis: ${deviceResult.riskScore} risk score`
      };
    } catch (error) {
      this.logger.error('Error in device fingerprint analysis:', error);
      return { isBot: false, confidence: 0, indicator: 'Device analysis error' };
    }
  }

  /**
   * Calculate overall risk score from all analyses
   */
  private calculateRiskScore(
    userAgentConfidence: number,
    timingConfidence: number,
    patternConfidence: number,
    sessionConfidence: number,
    deviceConfidence: number = 0,
  ): number {
    const totalWeight = this.config.userAgentWeight + 
                       this.config.timingWeight + 
                       this.config.patternWeight + 
                       this.config.sessionWeight +
                       this.config.deviceWeight;

    const weightedScore = 
      (userAgentConfidence * this.config.userAgentWeight) +
      (timingConfidence * this.config.timingWeight) +
      (patternConfidence * this.config.patternWeight) +
      (sessionConfidence * this.config.sessionWeight) +
      (deviceConfidence * this.config.deviceWeight);

    return weightedScore / totalWeight;
  }

  /**
   * Load bot detection patterns from database/configuration
   */
  private async loadBotPatterns(): Promise<void> {
    try {
      // Load any custom bot patterns from database
      // This could include tenant-specific bot detection rules
      this.logger.log('Bot patterns loaded');
    } catch (error) {
      this.logger.error('Error loading bot patterns:', error);
    }
  }

  /**
   * Map risk score to event severity
   */
  private mapRiskScoreToEventSeverity(score: number): 'INFO' | 'SECURITY' | 'CRITICAL' | 'ERROR' {
  // Define default thresholds as constants for clarity and fallback
  const DEFAULT_CRITICAL = 0.95;
  const DEFAULT_HIGH = 0.8;
  const DEFAULT_MEDIUM = 0.6;
  const DEFAULT_LOW = 0.3;

  // Use the configured value if it's a valid number, otherwise fall back to the default
  const critical = typeof this.config.riskScoreThresholds.critical === 'number' ? this.config.riskScoreThresholds.critical : DEFAULT_CRITICAL;
  const high =     typeof this.config.riskScoreThresholds.high === 'number' ?     this.config.riskScoreThresholds.high :     DEFAULT_HIGH;
  const medium =   typeof this.config.riskScoreThresholds.medium === 'number' ?   this.config.riskScoreThresholds.medium :   DEFAULT_MEDIUM;
  const low =      typeof this.config.riskScoreThresholds.low === 'number' ?      this.config.riskScoreThresholds.low :      DEFAULT_LOW;

  // Optional: Log the *effective* thresholds being used for this specific call for clarity
  // this.logger.debug(`Evaluating severity for score ${score} using effective thresholds: { low: ${low}, medium: ${medium}, high: ${high}, critical: ${critical} }`);

  if (score >= critical) return 'CRITICAL';
  if (score >= high)     return 'SECURITY';
  if (score >= medium)   return 'SECURITY';
  if (score >= low)      return 'SECURITY'; // With the fallback, 0.5 >= 0.3 will always be true here, returning 'SECURITY'
  return 'INFO';
}

  /**
   * Get default bot detection result (safe fallback)
   */
  private getDefaultBotDetectionResult(): BotDetectionResult {
    return {
      isBot: false,
      confidence: 0,
      indicators: [],
      riskScore: 0,
      recommendation: 'ALLOW',
      analysis: {
        userAgent: false,
        timing: false,
        navigation: false,
        requestPattern: false,
        sessionBehavior: false,
        deviceFingerprint: false,
      },
    };
  }

  /**
   * Get bot statistics for an IP address
   */
  async getBotStats(ipAddress: string): Promise<any> {
    // This would return bot detection statistics for the IP
    // Implementation would depend on your specific requirements
    return {
      totalBotDetections: 0,
      botConfidenceAverage: 0,
      lastBotDetection: null,
    };
  }

  /**
   * Challenge a suspected bot (CAPTCHA, JavaScript challenge, etc.)
   */
  async challengeBot(requestContext: any): Promise<boolean> {
    // This would implement various bot challenge mechanisms
    // Such as CAPTCHA, JavaScript challenges, etc.
    // For now, return success
    return true;
  }
}