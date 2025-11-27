// behavioral-analysis.service.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import * as Sentry from '@sentry/node';
import { BehavioralAnalysisService } from '../behavioral-analysis.service';
import { PrismaService } from '@/prisma/prisma.service';
import { EventLogService } from '@/events/event.service';
import { SecurityMonitoringService } from '@/security/security-monitor.service';
import { IPReputationService } from '@/ip-reputation/ip-reputation.service';
import { DeviceFingerprintingService } from '@/device-fingerprinting/device-fingerprinting.service';
import { EventType, EventSeverity } from '@/events/event.types';
import Redis from 'ioredis';
import { RedisService } from '@/redis/redis.service';

// Mock Sentry
jest.mock('@sentry/node', () => ({
  captureException: jest.fn(),
}));

describe('BehavioralAnalysisService', () => {
  let service: BehavioralAnalysisService;
  let prismaService: jest.Mocked<PrismaService>;
  let eventLogService: jest.Mocked<EventLogService>;
  let ipReputationService: jest.Mocked<IPReputationService>;
  let deviceFingerprintingService: jest.Mocked<DeviceFingerprintingService>;
  let redisService: jest.Mocked<Redis>;
  const mockUserId = 'user-123';
  const mockSessionId = 'session-456';
  const mockIP = '192.168.1.1';
  const mockUserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36';

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        BehavioralAnalysisService,
        {
          provide: PrismaService,
          useValue: {
            event: {
              findMany: jest.fn(),
            },
          },
        },
        {
            provide: RedisService, // <-- ADD THIS PROVIDER
            useValue: {
              get: jest.fn(),
              setex: jest.fn(),
              del: jest.fn(),
            },
        },
        {
          provide: EventLogService,
          useValue: {
            logEvent: jest.fn(),
          },
        },
        {
          provide: SecurityMonitoringService,
          useValue: {
            // Add methods as needed
          },
        },
        {
          provide: IPReputationService,
          useValue: {
            isIPBlocked: jest.fn(),
          },
        },
        {
          provide: DeviceFingerprintingService,
          useValue: {
            // Add methods as needed
          },
        },
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<BehavioralAnalysisService>(BehavioralAnalysisService);
    prismaService = module.get(PrismaService);
    eventLogService = module.get(EventLogService);
    ipReputationService = module.get(IPReputationService);
    deviceFingerprintingService = module.get(DeviceFingerprintingService);
    redisService = module.get(RedisService); 
    // Clear all mocks
    jest.clearAllMocks();
  });

  describe('Module lifecycle', () => {
    it('should be defined', () => {
      expect(service).toBeDefined();
    });

    it('should initialize successfully', async () => {
      prismaService.event.findMany.mockResolvedValue([]);
      
      await service.onModuleInit();
      
      expect(prismaService.event.findMany).toHaveBeenCalledWith({
        where: {
          createdAt: { gte: expect.any(Date) },
        },
        orderBy: { createdAt: 'desc' },
        take: 10000,
      });
    });

    it('should handle initialization errors gracefully', async () => {
      prismaService.event.findMany.mockRejectedValue(new Error('DB error'));
      
      await expect(service.onModuleInit()).resolves.not.toThrow();
    });

    it('should destroy successfully', async () => {
      await expect(service.onModuleDestroy()).resolves.not.toThrow();
    });
  });

  describe('analyzeRequest', () => {
    it('should analyze request and return anomaly result', async () => {
      ipReputationService.isIPBlocked.mockResolvedValue(false);

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
      expect(result.isAnomalous).toBeDefined();
      expect(result.confidence).toBeGreaterThanOrEqual(0);
      expect(result.confidence).toBeLessThanOrEqual(1);
      expect(result.recommendation).toMatch(/ALLOW|CHALLENGE|BLOCK/);
    });

    it('should create new session for first request', async () => {
      const result = await service.analyzeRequest(
        mockUserId,
        mockSessionId,
        mockIP,
        mockUserAgent,
        'GET',
        '/api/test',
        150
      );

      // Session should be created
      const sessionKey = mockSessionId;
      expect(service['behavioralSessions'].has(sessionKey)).toBe(true);
      
      const session = service['behavioralSessions'].get(sessionKey);
      expect(session?.userId).toBe(mockUserId);
      expect(session?.ipAddress).toBe(mockIP);
      expect(session?.totalRequests).toBe(1);
    });

    it('should update existing session for subsequent requests', async () => {
      // First request
      await service.analyzeRequest(
        mockUserId,
        mockSessionId,
        mockIP,
        mockUserAgent,
        'GET',
        '/api/test',
        150
      );

      // Second request
      await service.analyzeRequest(
        mockUserId,
        mockSessionId,
        mockIP,
        mockUserAgent,
        'POST',
        '/api/another',
        200
      );

      const session = service['behavioralSessions'].get(mockSessionId);
      expect(session?.totalRequests).toBe(2);
      expect(session?.navigationSequence).toContain('/api/test');
      expect(session?.navigationSequence).toContain('/api/another');
    });

    it('should handle requests without session ID', async () => {
      const result = await service.analyzeRequest(
        mockUserId,
        null,
        mockIP,
        mockUserAgent,
        'GET',
        '/api/test',
        150
      );

      expect(result).toBeDefined();
      // Should create session with generated key
      const sessionKey = `${mockIP}-${mockUserId}`;
      expect(service['behavioralSessions'].has(sessionKey)).toBe(true);
    });

    it('should handle errors gracefully and return default result', async () => {
        const mockError = new Error('Simulated internal failure within IP Reputation check');
        
        // --- FIX: Mock the correct dependency: ipReputationService.isIPBlocked ---
        // This is called inside analyzeIPBehavior, which is called inside analyzeRequest
        ipReputationService.isIPBlocked.mockRejectedValue(mockError);
        
        // Make sure Sentry mock is clear before this specific test runs
        (Sentry.captureException as jest.Mock).mockClear();
    
        const result = await service.analyzeRequest(
            'userId123', 
            'sessionId123', 
            '192.168.1.1', // Ensure IP address is provided to trigger the if (session.ipAddress) block
            'UA', 
            'GET', 
            '/', 
            0
        );
        
        // These assertions should now pass:
        // The service successfully handles the error internally and returns a default result:
        expect(result).toEqual(service['getDefaultAnomalyResult']()); 
        
        // The error should have been captured by Sentry:
        expect(Sentry.captureException).toHaveBeenCalledWith(mockError); 
      });
    

    it('should log event for behavioral analysis', async () => {
      await service.analyzeRequest(
        mockUserId,
        mockSessionId,
        mockIP,
        mockUserAgent,
        'GET',
        '/api/test',
        150
      );

      expect(eventLogService.logEvent).toHaveBeenCalledWith(
        'SECURITY_STATUS_CHECKED',
        expect.objectContaining({
          userId: mockUserId,
          ipAddress: mockIP,
          userAgent: mockUserAgent,
          metadata: expect.objectContaining({
            analysisType: 'BEHAVIORAL',
            riskScore: expect.any(Number),
            severity: expect.stringMatching(/LOW|MEDIUM|HIGH|CRITICAL/),
          }),
        })
      );
    });
  });

  describe('Risk score calculation', () => {
    it('should calculate risk score based on analysis results', () => {
      const timingAnalysis = {
        intervals: [100, 150, 200],
        isHumanLike: false, // This should increase risk
        entropy: 0.2,
        patterns: {
          regular: true,
          tooFast: false,
          tooConsistent: true,
        },
      };

      const navigationAnalysis = {
        sequence: ['/a', '/b', '/c'],
        isExpected: true,
        deviationScore: 0,
        commonPaths: [],
        anomalyDetected: false,
        expectedTransitions: 2,
        unexpectedTransitions: 0,
      };

      const rateAnalysis = { isAnomalous: false, rate: 5, burstiness: 0.3 };
      const ipAnalysis = { isAnomalous: false, indicators: [] };
      const sessionAnalysis = { isAnomalous: false, indicators: [] };

      const riskScore = service['calculateRiskScore'](
        timingAnalysis as any,
        navigationAnalysis as any,
        rateAnalysis,
        ipAnalysis,
        sessionAnalysis
      );

      // Timing anomaly weight should be applied
      expect(riskScore).toBeCloseTo(0.5); // timingAnomalyWeight
    });

    it('should cap risk score between 0 and 1', () => {
      // Test with all anomalies to get maximum score
      const timingAnalysis = { isHumanLike: false } as any;
      const navigationAnalysis = { anomalyDetected: true } as any;
      const rateAnalysis = { isAnomalous: true } as any;
      const ipAnalysis = { isAnomalous: true } as any;
      const sessionAnalysis = { isAnomalous: true } as any;

      const riskScore = service['calculateRiskScore'](
        timingAnalysis,
        navigationAnalysis,
        rateAnalysis,
        ipAnalysis,
        sessionAnalysis
      );

      expect(riskScore).toBeGreaterThanOrEqual(0);
      expect(riskScore).toBeLessThanOrEqual(1);
    });
  });

  describe('Session management', () => {
    it('should track sessions per IP', async () => {
      await service.analyzeRequest(
        'user1',
        'session1',
        mockIP,
        mockUserAgent,
        'GET',
        '/api/test',
        150
      );

      await service.analyzeRequest(
        'user2', 
        'session2',
        mockIP, // Same IP
        mockUserAgent,
        'GET',
        '/api/test',
        150
      );

      expect(service['ipSessionMap'].get(mockIP)?.size).toBe(2);
      expect(service['ipSessionMap'].get(mockIP)).toContain('session1');
      expect(service['ipSessionMap'].get(mockIP)).toContain('session2');
    });

    it('should track sessions per user', async () => {
      await service.analyzeRequest(
        mockUserId,
        'session1',
        '192.168.1.1',
        mockUserAgent,
        'GET',
        '/api/test',
        150
      );

      await service.analyzeRequest(
        mockUserId,
        'session2', // Same user, different session
        '192.168.1.2',
        mockUserAgent,
        'GET',
        '/api/test',
        150
      );

      expect(service['userSessionMap'].get(mockUserId)?.size).toBe(2);
    });
  });

  describe('Utility methods', () => {
    it('should map risk level to event severity correctly', () => {
      expect(service['mapRiskLevelToEventSeverity']('LOW')).toBe('INFO');
      expect(service['mapRiskLevelToEventSeverity']('MEDIUM')).toBe('SECURITY');
      expect(service['mapRiskLevelToEventSeverity']('HIGH')).toBe('SECURITY');
      expect(service['mapRiskLevelToEventSeverity']('CRITICAL')).toBe('CRITICAL');
    });

    it('should determine risk level from score', () => {
      expect(service['getRiskLevel'](0.1)).toBe('LOW');
      expect(service['getRiskLevel'](0.4)).toBe('MEDIUM');
      expect(service['getRiskLevel'](0.7)).toBe('HIGH');
      expect(service['getRiskLevel'](0.96)).toBe('CRITICAL');
    });
  });
});