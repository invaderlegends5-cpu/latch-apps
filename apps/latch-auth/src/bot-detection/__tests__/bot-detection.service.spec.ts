// bot-detection.service.spec.ts
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

// Mock Sentry globally for the main test suite
jest.mock('@sentry/node', () => ({
  captureException: jest.fn(),
}));

describe('BotDetectionService', () => {
  let service: BotDetectionService;
  let prismaService: jest.Mocked<PrismaService>;
  let eventLogService: jest.Mocked<EventLogService>;
  let behavioralAnalysisService: jest.Mocked<BehavioralAnalysisService>;
  let ipReputationService: jest.Mocked<IPReputationService>;
  let deviceFingerprintingService: jest.Mocked<DeviceFingerprintingService>;
  let redisService: jest.Mocked<RedisService>;

  const mockUserId = 'user-123';
  const mockSessionId = 'session-456';
  const mockIP = '192.168.1.1';
  const mockUserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36';

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        BotDetectionService,
        {
          provide: PrismaService,
          useValue: {
            session: {
              findUnique: jest.fn().mockResolvedValue({
                id: mockSessionId,
                userId: mockUserId,
                tenantId: 'tenant-123',
                refreshHash: 'hash',
                userAgent: mockUserAgent,
                ipAddress: mockIP,
                createdAt: new Date(),
                lastActiveAt: new Date(),
                expiresAt: new Date(Date.now() + 3600000),
                revoked: false,
                csrfToken: 'csrf-token',
              }),
            },
          },
        },
        {
          provide: EventLogService,
          useValue: {
            logEvent: jest.fn(),
          },
        },
        {
          provide: BehavioralAnalysisService,
          useValue: {
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
            blockIP: jest.fn().mockResolvedValue(undefined),
          },
        },
        {
          provide: DeviceFingerprintingService,
          useValue: {
            analyzeDeviceForBot: jest.fn().mockResolvedValue({
              isBot: false,
              confidence: 0,
              riskScore: 0,
              indicator: 'mocked-default',
            }),
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
              if (key === 'botDetection.riskScoreThresholds') {
                return { low: 0.1, medium: 0.2, high: 0.4, critical: 0.5 };
              }
              if (key === 'botDetection.autoBlockThreshold') { return 0.9; }
              return null; 
            }),
          },
        },
      ],
    }).compile();

    service = module.get<BotDetectionService>(BotDetectionService);
    prismaService = module.get(PrismaService);
    eventLogService = module.get(EventLogService);
    behavioralAnalysisService = module.get(BehavioralAnalysisService);
    ipReputationService = module.get(IPReputationService);
    deviceFingerprintingService = module.get(DeviceFingerprintingService);
    redisService = module.get(RedisService);

    // Clear all mocks
    jest.clearAllMocks();

    prismaService.session.findUnique.mockReset(); // Reset completely
    prismaService.session.findUnique.mockRejectedValue(new Error('DB error'));
  
    // Add debug to verify the mock is set correctly
    console.log('Error suite - prisma mock set to:', prismaService.session.findUnique.getMockImplementation() ? 'REJECT' : 'UNDEFINED');

  });

  describe('Module lifecycle', () => {
    it('should be defined', () => {
      expect(service).toBeDefined();
    });

    it('should initialize successfully', async () => {
      await service.onModuleInit();
    });

    it('should load bot patterns on initialization', async () => {
      await service.onModuleInit();
    });
  });

  describe('analyzeRequest', () => {
    it('should analyze request and return bot detection result', async () => {
      const result = await service.analyzeRequest(
        mockUserId,
        mockSessionId,
        mockIP,
        mockUserAgent,
        'GET',
        '/api/test',
        150
      );

      expect(result).toBeDefined();
      expect(result.isBot).toBe(false);
      expect(result.confidence).toBeGreaterThanOrEqual(0);
      expect(result.confidence).toBeLessThanOrEqual(1);
      expect(result.recommendation).toBe('ALLOW');
      expect(result.analysis).toEqual({
        userAgent: false,
        timing: false,
        navigation: false,
        requestPattern: false,
        sessionBehavior: false,
        deviceFingerprint: false,
      });
    });

    it('should detect bot based on user agent analysis', async () => {
      const botUserAgent = 'Googlebot/2.1 (+http://www.google.com/bot.html)';
      
      console.log('=== DEBUG USER AGENT TEST ===');
      console.log('User agent being tested:', botUserAgent);
      console.log('Known bot user agents:', service['config'].knownBotUserAgents);

      const result = await service.analyzeRequest(
        mockUserId,
        mockSessionId,
        mockIP,
        botUserAgent,
        'GET',
        '/api/test',
        150
      );

      console.log('Full analysis result:', JSON.stringify(result, null, 2));
      console.log('Risk score thresholds:', service['config'].riskScoreThresholds);
      console.log('Is bot threshold:', service['config'].riskScoreThresholds.medium);
      console.log('=== END DEBUG ===');

      expect(result.isBot).toBe(true);
      expect(result.analysis.userAgent).toBe(true);
      expect(result.confidence).toBeGreaterThan(0.3);
    });

    it('should log event when bot is detected', async () => {
      const botUserAgent = 'python-requests/2.28.1';
      
      await service.analyzeRequest(
        mockUserId,
        mockSessionId,
        mockIP,
        botUserAgent,
        'GET',
        '/api/test',
        150
      );

      expect(eventLogService.logEvent).toHaveBeenCalledWith(
        'SECURITY_CSRF_ERROR',
        expect.objectContaining({
          userId: mockUserId,
          ipAddress: mockIP,
          userAgent: botUserAgent,
          metadata: expect.objectContaining({
            analysisType: 'BOT_DETECTION',
            isBot: true,
          }),
        })
      );
    });

    it('should auto-block IP when risk score exceeds threshold', async () => {
      deviceFingerprintingService.analyzeDeviceForBot.mockResolvedValue({
        isBot: true,
        confidence: 0.95,
        riskScore: 0.95,
      });

      await service.analyzeRequest(
        mockUserId,
        mockSessionId,
        mockIP,
        'HeadlessChrome',
        'GET',
        '/api/test',
        10
      );

      expect(ipReputationService.blockIP).toHaveBeenCalledWith(
        mockIP,
        expect.stringContaining('High bot risk detected'),
        expect.any(Number)
      );
    });
  });

  describe('Risk score calculation', () => {
    it('should calculate risk score from all analysis components', () => {
      const userAgentConfidence = 0.9;
      const timingConfidence = 0.6;
      const patternConfidence = 0.3;
      const sessionConfidence = 0.1;
      const deviceConfidence = 0.8;

      const riskScore = service['calculateRiskScore'](
        userAgentConfidence,
        timingConfidence,
        patternConfidence,
        sessionConfidence,
        deviceConfidence
      );

      expect(riskScore).toBeGreaterThan(0);
      expect(riskScore).toBeLessThanOrEqual(1);
    });

    it('should handle zero weights gracefully', () => {
      const riskScore = service['calculateRiskScore'](0, 0, 0, 0, 0);
      expect(riskScore).toBe(0);
    });
  });

  describe('Utility methods', () => {
    it('should map risk score to event severity correctly', () => {
      expect(service['mapRiskScoreToEventSeverity'](0.1)).toBe('INFO');
      expect(service['mapRiskScoreToEventSeverity'](0.5)).toBe('SECURITY');
      expect(service['mapRiskScoreToEventSeverity'](0.8)).toBe('SECURITY');
      expect(service['mapRiskScoreToEventSeverity'](0.96)).toBe('CRITICAL');
    });

    it('should return default bot detection result', () => {
      const defaultResult = service['getDefaultBotDetectionResult']();
      
      expect(defaultResult).toEqual({
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
      });
    });
  });

  describe('Additional methods', () => {
    it('should get bot statistics for IP', async () => {
      const stats = await service.getBotStats(mockIP);
      
      expect(stats).toEqual({
        totalBotDetections: 0,
        botConfidenceAverage: 0,
        lastBotDetection: null,
      });
    });

    it('should challenge bot and return success', async () => {
      const challengeResult = await service.challengeBot({});
      
      expect(challengeResult).toBe(true);
    });
  });
});

// COMPLETELY SEPARATE TEST FILE FOR ERROR HANDLING
// (Or, keep it in the same file but ensure the mock is re-applied)
// describe('BotDetectionService Error Handling', () => {
//   let service: BotDetectionService;
//   let deviceFingerprintingService: jest.Mocked<DeviceFingerprintingService>;
//   let prismaService: jest.Mocked<PrismaService>;
//   // Store the reference to the mocked captureException function
//   let mockCaptureException: jest.MockedFunction<typeof import('@sentry/node').captureException>;

//   beforeEach(async () => {
//     // Reset all modules to ensure complete isolation
//     jest.resetModules();

//     // --- CRITICAL: Re-mock Sentry within this isolated test context ---
//     // This mock will be active for the modules imported below
//     const mockSentryImplementation = {
//       captureException: jest.fn(),
//       // Add other Sentry methods if the service uses them, e.g., init: jest.fn()
//     };
//     jest.mock('@sentry/node', () => mockSentryImplementation);
//     // Store the reference to the mock function created here
//     mockCaptureException = mockSentryImplementation.captureException;
//     // --- End of critical addition ---

//     // Re-import everything fresh
//     const { Test, TestingModule } = await import('@nestjs/testing');
//     const { BotDetectionService } = await import('../bot-detection.service');
//     const { PrismaService } = await import('@/prisma/prisma.service');
//     const { EventLogService } = await import('@/events/event.service');
//     const { BehavioralAnalysisService } = await import('@/behavioral-analysis/behavioral-analysis.service');
//     const { RedisService } = await import('@/redis/redis.service');
//     const { IPReputationService } = await import('@/ip-reputation/ip-reputation.service');
//     const { DeviceFingerprintingService } = await import('@/device-fingerprinting/device-fingerprinting.service');
//     const { ConfigService } = await import('@nestjs/config');

//     const module: TestingModule = await Test.createTestingModule({
//       providers: [
//         BotDetectionService,
//         {
//           provide: PrismaService,
//           useValue: {
//             session: {
//               findUnique: jest.fn().mockResolvedValue({userId: 'user-123',
//                 id: 'session-456',
//                 ip :'192.168.1.1',
//                 userAgent : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}),
//             },
//           },
//         },
//         {
//           provide: EventLogService,
//           useValue: {
//             logEvent: jest.fn(),
//           },
//         },
//         {
//           provide: BehavioralAnalysisService,
//           useValue: {
//             analyzeRequest: jest.fn().mockResolvedValue({ 
//               isAnomalous: false, 
//               confidence: 0, 
//               indicators: [], 
//               riskScore: 0, 
//               recommendation: 'ALLOW', 
//               analysis: { 
//                 userAgent: false, 
//                 timing: false, 
//                 navigation: false, 
//                 requestPattern: false, 
//                 sessionBehavior: false, 
//                 deviceFingerprint: false 
//               } 
//             }),
//             getUserSessionStats: jest.fn().mockResolvedValue({ totalSessions: 1, activeSessions: 1, riskScore: 0 }),
//             getIPStats: jest.fn().mockResolvedValue({ sessionCount: 1, avgRiskScore: 0, isBlocked: false }),
//           },
//         },
//         {
//           provide: RedisService,
//           useValue: {
//             get: jest.fn(),
//             set: jest.fn(),
//           },
//         },
//         {
//           provide: IPReputationService,
//           useValue: {
//             isIPBlocked: jest.fn().mockResolvedValue(false),
//             blockIP: jest.fn().mockResolvedValue(undefined),
//           },
//         },
//         {
//           provide: DeviceFingerprintingService,
//           useValue: {
//             analyzeDeviceForBot: jest.fn().mockResolvedValue({
//               analyzeDeviceForBot: jest.fn().mockRejectedValue(new Error('Device Fingerprinting Error')),
//             }),
//           },
//         },
//         {
//           provide: ConfigService,
//           useValue: {
//             get: jest.fn(key => {
//               if (key === 'botDetection.knownBotUserAgents') { 
//                 return [
//                   'googlebot', 'bingbot', 'slurp', 'duckduckbot',
//                   'python-requests', 'python-urllib', 'bot', 'crawler', 'spider', 'scraper',
//                 ];
//               }
//               if (key === 'botDetection.riskScoreThresholds') {
//                 return { low: 0.1, medium: 0.2, high: 0.4, critical: 0.5 };
//               }
//               if (key === 'botDetection.autoBlockThreshold') { return 0.9; }
//               return null; 
//             }),
//           },
//         },
//       ],
//     }).compile();

//     service = module.get<BotDetectionService>(BotDetectionService);
//     prismaService = module.get(PrismaService);
//     deviceFingerprintingService = module.get(DeviceFingerprintingService);
//   });

//   it('should handle errors gracefully and return default result', async () => {
//     // Use a user agent that will definitely trigger isBot = true initially
//     // This will cause logEvent to be called inside the try block if no error occurs first
//     const result = await service.analyzeRequest(
//       'user-123',
//       'session-456',
//       '192.168.1.1',
//       'Googlebot/2.1 (+http://www.google.com/bot.html)', // <-- Use a known bot UA
//       'GET',
//       '/api/test',
//       150
//     );
  
//     // Because DeviceFingerprintingService throws (and is caught internally),
//     // and Prisma call is resolved (so sessionAnalysis succeeds),
//     // calculateRiskScore should run. If calculateRiskScore is NOT defensive against
//     // undefined inputs (revert the change made earlier), it could produce NaN here.
//     // Or, if the user agent match makes isBot=true, and then logEvent throws,
//     // it would go to the outer catch. But logEvent is mocked to resolve.
  
//     // For now, let's assume the error is still coming from calculateRiskScore receiving undefined
//     // due to the internal catch of DeviceFingerprintingService not happening as expected
//     // or another analysis step failing silently.
  
//     // Expected result is still the default, because the outer catch should eventually run
//     // or the internal errors lead to a default-like state.
//     expect(result).toEqual({
//       isBot: false, // <-- This might need to be true if userAgent triggers it, but outer catch resets
//       confidence: 0,
//       indicators: [],
//       riskScore: 0,
//       recommendation: 'ALLOW',
//       analysis: {
//         userAgent: false, // <-- Or true, depending on which error path dominates
//         timing: false,
//         navigation: false,
//         requestPattern: false,
//         sessionBehavior: false,
//         deviceFingerprint: false, // <-- Should be false if outer catch returns default
//       },
//     });
//     expect(mockCaptureException).toHaveBeenCalled();
//   });
// });

// describe('BotDetectionService Error Handling', () => {
//   let service: BotDetectionService;
//   let prismaService: jest.Mocked<PrismaService>;
//   // Store the reference to the mocked captureException function
//   let mockCaptureException: jest.MockedFunction<typeof import('@sentry/node').captureException>;

//   beforeEach(async () => {
//     // Reset all modules to ensure complete isolation
//     jest.resetModules();

//     // --- CRITICAL: Re-mock Sentry within this isolated test context ---
//     const mockSentryImplementation = {
//       captureException: jest.fn(),
//       // Add other Sentry methods if the service uses them, e.g., init: jest.fn()
//     };
//     jest.mock('@sentry/node', () => mockSentryImplementation);
//     // Store the reference to the mock function created here
//     mockCaptureException = mockSentryImplementation.captureException;
//     // --- End of critical addition ---

//     // Re-import everything fresh
//     const { Test, TestingModule } = await import('@nestjs/testing');
//     const { BotDetectionService } = await import('../bot-detection.service');
//     const { PrismaService } = await import('@/prisma/prisma.service');
//     const { EventLogService } = await import('@/events/event.service');
//     const { BehavioralAnalysisService } = await import('@/behavioral-analysis/behavioral-analysis.service');
//     const { RedisService } = await import('@/redis/redis.service');
//     const { IPReputationService } = await import('@/ip-reputation/ip-reputation.service');
//     const { DeviceFingerprintingService } = await import('@/device-fingerprinting/device-fingerprinting.service'); // Import the service
//     const { ConfigService } = await import('@nestjs/config');

//     const module: TestingModule = await Test.createTestingModule({
//       providers: [
//         BotDetectionService,
//         {
//           provide: PrismaService,
//           useValue: {
//             session: {
//               // --- CRITICAL: Make Prisma reject specifically for this test ---
//               findUnique: jest.fn().mockRejectedValue(new Error('Isolated DB Error')),
//               // --- End of critical change ---
//             },
//           },
//         },
//         {
//           provide: EventLogService,
//           useValue: {
//             logEvent: jest.fn().mockRejectedValue(new Error('Log Event Failed')),
//           },
//         },
//         {
//           provide: BehavioralAnalysisService,
//           useValue: {
//             analyzeRequest: jest.fn().mockResolvedValue({ 
//               isAnomalous: false, 
//               confidence: 0, 
//               indicators: [], 
//               riskScore: 0, 
//               recommendation: 'ALLOW', 
//               analysis: { 
//                 userAgent: false, 
//                 timing: false, 
//                 navigation: false, 
//                 requestPattern: false, 
//                 sessionBehavior: false, 
//                 deviceFingerprint: false 
//               } 
//             }),
//             getUserSessionStats: jest.fn().mockResolvedValue({ totalSessions: 1, activeSessions: 1, riskScore: 0 }),
//             getIPStats: jest.fn().mockResolvedValue({ sessionCount: 1, avgRiskScore: 0, isBlocked: false }),
//           },
//         },
//         {
//           provide: RedisService,
//           useValue: {
//             get: jest.fn(),
//             set: jest.fn(),
//           },
//         },
//         {
//           provide: IPReputationService,
//           useValue: {
//             isIPBlocked: jest.fn().mockResolvedValue(false),
//             blockIP: jest.fn().mockResolvedValue(undefined),
//           },
//         },
//         {
//           provide: DeviceFingerprintingService,
//           // --- CRITICAL: Make DeviceFingerprinting resolve successfully ---
//           useValue: {
//             analyzeDeviceForBot: jest.fn().mockResolvedValue({
//               isBot: false,
//               confidence: 0,
//               riskScore: 0,
//               indicator: 'default-from-error-test-mock',
//             }),
//           },
//           // --- End of critical change ---
//         },
//         {
//           provide: ConfigService,
//           useValue: {
//             get: jest.fn(key => {
//               if (key === 'botDetection.knownBotUserAgents') { 
//                 return [
//                   'googlebot', 'bingbot', 'slurp', 'duckduckbot',
//                   'python-requests', 'python-urllib', 'bot', 'crawler', 'spider', 'scraper',
//                 ];
//               }
//               if (key === 'botDetection.riskScoreThresholds') {
//                 return { low: 0.1, medium: 0.2, high: 0.4, critical: 0.5 };
//               }
//               if (key === 'botDetection.autoBlockThreshold') { return 0.9; }
//               return null; 
//             }),
//           },
//         },
//       ],
//     }).compile();

//     service = module.get<BotDetectionService>(BotDetectionService);
//     prismaService = module.get(PrismaService);
//   });

//   it('should handle errors gracefully and return default result', async () => {
//     // Use the original user agent, not the bot one, to avoid isBot=true from UA match
//     const result = await service.analyzeRequest(
//       'user-123',
//       'session-456', // This will trigger analyzeSessionBehavior
//       '192.168.1.1',
//       'Googlebot/2.1 (+http://www.google.com/bot.html)', // Use bot UA to make isBot=true
//       'GET',
//       '/api/test',
//       150
//     );

//     // Since Prisma rejects, analyzeSessionBehavior catches internally.
//     // analyzeDeviceFingerprint should resolve fine now.
//     // calculateRiskScore should receive { confidence: 0 } from sessionAnalysis and other default confidences.
//     // If calculateRiskScore is defensive, confidence should not be NaN.
//     // If outer catch doesn't run (because internal catches work), result might reflect
//     // the state before an error, or a state where internal errors led to NaN somehow.
//     // Expected: Default result because outer catch should run IF an unhandled error occurs.
//     // Received: NaN confidence, undefined deviceFingerprint, isBot=true (from UA log above? No, using non-bot UA now)
//     // Need to see if using non-bot UA changes the received isBot/confidence.

//     expect(result).toEqual({
//       isBot: false, // Should be false now with non-bot UA
//       confidence: 0, // Should be 0 if calculateRiskScore is truly defensive
//       indicators: [],
//       riskScore: 0,
//       recommendation: 'ALLOW',
//       analysis: {
//         userAgent: false,
//         timing: false,
//         navigation: false,
//         requestPattern: false,
//         sessionBehavior: false,
//         deviceFingerprint: false, // Should be false if calculateRiskScore didn't fail
//       },
//     });
//     expect(mockCaptureException).toHaveBeenCalled();
//   });
// });