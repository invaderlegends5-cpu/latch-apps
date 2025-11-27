// bot-detection.service.error.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import * as Sentry from '@sentry/node';
import { BotDetectionService } from '../bot-detection.service';
import { PrismaService } from '@/prisma/prisma.service';
import { EventLogService } from '@/events/event.service';
import { BehavioralAnalysisService } from '@/behavioral-analysis/behavioral-analysis.service';
import { RedisService } from '@/redis/redis.service';
import { IPReputationService } from '@/ip-reputation/ip-reputation.service';
import { DeviceFingerprintingService } from '@/device-fingerprinting/device-fingerprinting.service';

// Mock Sentry
jest.mock('@sentry/node', () => ({
  captureException: jest.fn(),
}));

describe('BotDetectionService Error Handling (Non-Bot UA via High Score)', () => {
  let service: BotDetectionService;
  let eventLogService: jest.Mocked<EventLogService>; // Get the mocked instance

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        BotDetectionService,
        {
          provide: PrismaService,
          useValue: {
            session: {
              // Resolve Prisma call to allow normal flow
              findUnique: jest.fn().mockResolvedValue({ id: 'session-456', userId: 'user-123' /* ... other props ... */ }),
            },
          },
        },
        {
          provide: EventLogService,
          useValue: {
            // --- CRITICAL: Mock logEvent to reject, simulating a logging failure ---
            logEvent: jest.fn().mockRejectedValue(new Error('Log Event Failed')),
            // --- End of critical change ---
          },
        },
        {
          provide: BehavioralAnalysisService,
          useValue: {
            // Keep other mocks if necessary for setup, but ensure they don't throw
            analyzeRequest: jest.fn().mockResolvedValue({ 
              isAnomalous: false, 
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
                deviceFingerprint: false 
              } 
            }),
            getUserSessionStats: jest.fn().mockResolvedValue({ totalSessions: 1, activeSessions: 1, riskScore: 0 }),
            getIPStats: jest.fn().mockResolvedValue({ sessionCount: 1, avgRiskScore: 0, isBlocked: false }),
          },
        },
        {
          provide: RedisService,
          useValue: {
            get: jest.fn(),
            set: jest.fn(),
          },
        },
        {
          provide: IPReputationService,
          useValue: {
            isIPBlocked: jest.fn().mockResolvedValue(false),
            // blockIP should resolve fine for this test, as we are targeting logEvent failure
            blockIP: jest.fn().mockResolvedValue(undefined),
          },
        },
        {
          provide: DeviceFingerprintingService,
          useValue: {
            // --- CRITICAL: Mock to return a HIGH confidence to push risk score above medium threshold ---
            analyzeDeviceForBot: jest.fn().mockResolvedValue({
              isBot: true, // Doesn't matter much for risk score calc, but makes sense if confidence is high
              confidence: 0.95, // High confidence (weight 0.2): 0.95 * 0.2 = 0.19
              riskScore: 0.95,  // High risk score
              indicator: 'High risk fingerprint',
            }),
            // --- End of critical change ---
          },
        },
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn(key => {
              if (key === 'botDetection.knownBotUserAgents') { 
                return [
                  'googlebot', 'bingbot', 'slurp', 'duckduckbot',
                  'python-requests', 'python-urllib', 'bot', 'crawler', 'spider', 'scraper',
                ];
              }
              // --- CRITICAL: Lower the MEDIUM threshold so the high device score triggers isBot=true ---
              if (key === 'botDetection.riskScoreThresholds') {
                  return { low: 0.1, medium: 0.15, high: 0.4, critical: 0.5 }; // Lowered medium
              }
              // autoBlockThreshold can be default or high, doesn't matter for logEvent path
              if (key === 'botDetection.autoBlockThreshold') { return 0.9; }
              return null; 
            }),
          },
        },
      ],
    }).compile();

    service = module.get<BotDetectionService>(BotDetectionService);
    // Get the mocked instance to verify calls if needed
    eventLogService = module.get(EventLogService);
  });

  it('should handle errors from EventLogService when risk score triggers bot detection (non-bot UA)', async () => {
    // Use the NON-BOT user agent: 'Mozilla/5.0 ...'
    // analyzeUserAgent will return { isBot: false, confidence: 0 }
    // analyzeDeviceFingerprint is mocked to return { confidence: 0.95 }
    // With mediumThreshold mocked to 0.15, and riskScore likely > 0.15 due to high device confidence,
    // the 'isBot' determination (isBot = riskScore > mediumThreshold || userAgentAnalysis.isBot)
    // will be TRUE because riskScore > 0.15.
    // This should trigger the 'if (isBot)' block and call eventLog.logEvent.
    // eventLog.logEvent is mocked to reject, triggering the outer catch.
    const result = await service.analyzeRequest(
      'user-123',
      'session-456',
      '192.168.1.1',
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36', // Non-bot UA
      'GET',
      '/api/test',
      150
    );

    // Because the calculated riskScore (influenced by the high device fingerprint confidence)
    // should exceed the mocked mediumThreshold (0.15), the 'isBot' variable becomes true.
    // The 'if (isBot)' block executes, calling eventLog.logEvent.
    // eventLog.logEvent is mocked to reject.
    // This rejection should propagate up to the outer try...catch in analyzeRequest.
    // The catch block should log the error, call Sentry.captureException,
    // and return getDefaultBotDetectionResult().

    expect(result).toEqual({
      isBot: false, // Expected from getDefaultBotDetectionResult()
      confidence: 0,
      indicators: [],
      riskScore: 0,
      recommendation: 'ALLOW',
      analysis: {
        userAgent: false, // Reflects the *default* result after outer catch
        timing: false,
        navigation: false,
        requestPattern: false,
        sessionBehavior: false,
        deviceFingerprint: false, // Reflects the default result, not the state before the error
      },
    });
    // This assertion checks if the outer catch block correctly called Sentry
    expect(Sentry.captureException).toHaveBeenCalled();
    // Optional: Verify logEvent was called
    expect(eventLogService.logEvent).toHaveBeenCalledWith(
        'SECURITY_CSRF_ERROR', // Expected event type for blocking action
        expect.objectContaining({
          userId: null, // userId is null in the handleHighRiskIP log call
          ipAddress: '192.168.1.1', // The IP being blocked
          userAgent: null, // userAgent is null in the handleHighRiskIP log call
          metadata:  expect.objectContaining({
            reason: 'auto_block_high_risk_bot_ip', // Specific reason for the blocking log
            // ... other expected metadata for the blocking action ...
          }),
        })
      );
  });
});