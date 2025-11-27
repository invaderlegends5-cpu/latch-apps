// ip-reputation.service.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { CronExpression } from '@nestjs/schedule';
import * as Sentry from '@sentry/node';
import { IPReputationService } from '../ip-reputation.service';
import { PrismaService } from '@/prisma/prisma.service';
import { EventLogService } from '@/events/event.service';
import { SecurityMonitoringService } from '@/security/security-monitor.service';
import { RedisService } from '@/redis/redis.service';
import { IP_REPUTATION_CONFIG, RISK_LEVEL_THRESHOLDS, THREAT_INDICATORS } from '../constants/reputation.constants';
import { EventType } from '@/events/event.types';
import { IPReputationScore, ReputationQueryOptions, ReputationUpdateResult } from '../types/reputation.types';

// Mock Sentry
jest.mock('@sentry/node', () => ({
  captureException: jest.fn(),
}));

describe('IPReputationService', () => {
  let service: IPReputationService;
  let prismaService: jest.Mocked<PrismaService>;
  let eventLogService: jest.Mocked<EventLogService>;
  let redisService: jest.Mocked<RedisService>;
  let configService: jest.Mocked<ConfigService>;
  let securityMonitorService: jest.Mocked<SecurityMonitoringService>;

  const mockIP = '192.168.1.1';
  const mockEvents = [
    {
      id: '1',
      type: 'AUTH_JWT_FAILURE' as EventType,
      ipAddress: mockIP,
      severity: 'SECURITY',
      metadata: {},
      createdAt: new Date(Date.now() - 2 * 60 * 60 * 1000), // 2 hours ago
      updatedAt: new Date(),
      userId: null,
      tenantId: null,
      sessionId: null,
      familyId: null,
      reason: null,
      integrityHash: 'hash1',
      prevHash: null,
      userAgent: null,
    },
    {
      id: '2',
      type: 'OTP_FAILED' as EventType,
      ipAddress: mockIP,
      severity: 'SECURITY',
      metadata: {},
      createdAt: new Date(Date.now() - 1 * 60 * 60 * 1000), // 1 hour ago
      updatedAt: new Date(),
      userId: null,
      tenantId: null,
      sessionId: null,
      familyId: null,
      reason: null,
      integrityHash: 'hash2',
      prevHash: null,
      userAgent: null,
    },
  ];

  const mockReputationScore: IPReputationScore = {
    ip: mockIP,
    score: 85,
    riskLevel: 'MEDIUM',
    totalEvents: 10,
    securityEvents: 3,
    lastUpdated: new Date(),
    eventCounts: {
      AUTH_JWT_FAILURE: 2,
      OTP_FAILED: 3,
      LOGIN: 5,
    } as Record<EventType, number>,
    threatIndicators: [],
    reputationHistory: [],
    blocked: false,
    whitelisted: false,
    metadata: {
      lastEvent: new Date(),
      firstEvent: new Date(Date.now() - 24 * 60 * 60 * 1000),
    },
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        IPReputationService,
        {
          provide: PrismaService,
          useValue: {
            event: {
              findMany: jest.fn(),
              findFirst: jest.fn(),
            },
            iPBlock: {
              findFirst: jest.fn(),
              upsert: jest.fn(),
              deleteMany: jest.fn(),
            },
            iPWhitelist: {
              findFirst: jest.fn(),
              upsert: jest.fn(),
              deleteMany: jest.fn(),
            },
            $transaction: jest.fn(),
          },
        },
        {
          provide: EventLogService,
          useValue: {
            logEvent: jest.fn(),
            event$: {
              subscribe: jest.fn(),
            },
          },
        },
        {
          provide: SecurityMonitoringService,
          useValue: {
            // Add methods as needed
          },
        },
        {
          provide: RedisService,
          useValue: {
            get: jest.fn(),
            setex: jest.fn(),
            del: jest.fn(),
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

    service = module.get<IPReputationService>(IPReputationService);
    prismaService = module.get(PrismaService);
    eventLogService = module.get(EventLogService);
    redisService = module.get(RedisService);
    configService = module.get(ConfigService);
    securityMonitorService = module.get(SecurityMonitoringService);

    // Clear all mocks
    jest.clearAllMocks();
  });

  describe('Module lifecycle', () => {
    it('should be defined', () => {
      expect(service).toBeDefined();
    });

    it('should initialize successfully and warmup cache', async () => {
      prismaService.event.findMany.mockResolvedValue([]);
      redisService.setex.mockResolvedValue(undefined);
      
      await service.onModuleInit();
      
      expect(prismaService.event.findMany).toHaveBeenCalledWith({
        where: {
          ipAddress: { not: null },
          type: { in: ['TOKEN_REUSE', 'SECURITY_CSRF_MISMATCH', 'AUTH_JWT_FAILURE'] },
          createdAt: { gte: expect.any(Date) },
        },
        select: { ipAddress: true },
        distinct: ['ipAddress'],
        take: 100,
      });
      expect(eventLogService.event$.subscribe).toHaveBeenCalled();
    });

    it('should handle initialization errors gracefully', async () => {
        // Fix: Create error outside the test function scope to avoid any scope issues
        const warmupError = new Error('DB error');
        
        prismaService.event.findMany.mockRejectedValue(warmupError);
        
        const loggerErrorSpy = jest.spyOn(service['logger'], 'error').mockImplementation();
        const sentryMock = Sentry.captureException as jest.MockedFunction<typeof Sentry.captureException>;
        
        await expect(service.onModuleInit()).rejects.toThrow('DB error');
        
        // Verify error was handled internally
        expect(loggerErrorSpy).toHaveBeenCalledWith('Cache warmup error:', warmupError);
        
        // SECURITY: Verify error was reported to monitoring
        expect(sentryMock).toHaveBeenCalledWith(warmupError, expect.objectContaining({
          tags: expect.objectContaining({
            component: 'ip-reputation',
            phase: 'initialization'
          })
        }));
        
        loggerErrorSpy.mockRestore();
      });

    it('should destroy successfully', async () => {
      await expect(service.onModuleDestroy()).resolves.not.toThrow();
    });
  });

  describe('getReputation', () => {
    it('should return cached reputation when available', async () => {
        // Create a version with string dates to simulate Redis serialization
        const cachedReputation = {
          ...mockReputationScore,
          lastUpdated: mockReputationScore.lastUpdated.toISOString(),
          metadata: {
            lastEvent: mockReputationScore.metadata.lastEvent.toISOString(),
            firstEvent: mockReputationScore.metadata.firstEvent.toISOString(),
          },
          reputationHistory: mockReputationScore.reputationHistory.map(hist => ({
            ...hist,
            timestamp: hist.timestamp.toISOString()
          }))
        };
        
        redisService.get.mockResolvedValue(JSON.stringify(cachedReputation));
      
        const result = await service.getReputation(mockIP);
      
        // Compare essential properties instead of full object
        expect(result?.ip).toBe(mockReputationScore.ip);
        expect(result?.score).toBe(mockReputationScore.score);
        expect(result?.riskLevel).toBe(mockReputationScore.riskLevel);
        expect(redisService.get).toHaveBeenCalledWith('ip-reputation:192.168.1.1');
        expect(prismaService.event.findMany).not.toHaveBeenCalled();
      });

      it('should calculate reputation when not cached', async () => {
        redisService.get.mockResolvedValue(null);
        
        // SECURITY: Ensure we return proper array structure
        prismaService.event.findMany.mockResolvedValue(mockEvents);
        prismaService.iPBlock.findFirst.mockResolvedValue(null);
        prismaService.iPWhitelist.findFirst.mockResolvedValue(null);
      
        const result = await service.getReputation(mockIP);
      
        expect(result).toBeDefined();
        expect(result?.ip).toBe(mockIP);
        expect(prismaService.event.findMany).toHaveBeenCalledWith({
          where: {
            ipAddress: mockIP,
            createdAt: { gte: expect.any(Date) },
          },
          orderBy: { createdAt: 'desc' },
        });
        
        // Fix: Check that the mock was called and resolved properly
        expect(prismaService.event.findMany).toHaveBeenCalled();
        expect(redisService.setex).toHaveBeenCalled();
      });

      it('should handle errors gracefully and return null', async () => {
        const mockError = new Error('Database connection failed during getReputation');

        // Mock the internal call to throw the error
        // We assume prismaService.event.findMany is called within the calculateReputation flow
        prismaService.event.findMany.mockRejectedValue(mockError);

        // Also ensure Redis miss is simulated so it hits the DB logic
        redisService.get.mockResolvedValue(null);

        // Ensure Sentry mock is clear before this specific test runs
        (Sentry.captureException as jest.Mock).mockClear();

        const result = await service.getReputation(mockIP);

        expect(result).toBeNull();
        // Verify Sentry was called with the specific error
        expect(Sentry.captureException).toHaveBeenCalledWith(mockError, expect.any(Object)); 
      });
  });

  describe('updateReputation', () => {
    beforeEach(() => {
      jest.spyOn(service, 'getReputation').mockResolvedValue(mockReputationScore);
      jest.spyOn(service as any, 'calculateReputation').mockResolvedValue({
        ...mockReputationScore,
        score: 350, // Critical score
      });
      jest.spyOn(service, 'isIPWhitelisted').mockResolvedValue(false);
      jest.spyOn(service, 'isIPBlocked').mockResolvedValue(false);
      jest.spyOn(service, 'blockIP').mockResolvedValue(undefined);
    });

    it('should update reputation and block IP when score becomes critical', async () => {
      const result = await service.updateReputation(mockIP, 'AUTH_JWT_FAILURE');

      expect(result.actionTaken).toBe('BLOCKED');
      expect(result.reason).toBe('Critical reputation score threshold exceeded');
      expect(service.blockIP).toHaveBeenCalledWith(
        mockIP,
        'CRITICAL_REPUTATION_SCORE',
        IP_REPUTATION_CONFIG.blocking.blockDuration
      );
    });

    it('should not block whitelisted IPs even with critical score', async () => {
      jest.spyOn(service, 'isIPWhitelisted').mockResolvedValue(true);

      const result = await service.updateReputation(mockIP, 'AUTH_JWT_FAILURE');

      expect(result.actionTaken).toBe('NONE');
      expect(service.blockIP).not.toHaveBeenCalled();
    });

    it('should unblock IP when score improves', async () => {
      jest.spyOn(service as any, 'calculateReputation').mockResolvedValue({
        ...mockReputationScore,
        score: 30, // Below medium threshold
      });
      jest.spyOn(service, 'isIPBlocked').mockResolvedValue(true);
      jest.spyOn(service, 'unblockIP').mockResolvedValue(undefined);

      const result = await service.updateReputation(mockIP, 'LOGIN');

      expect(result.actionTaken).toBe('UNBLOCKED');
      expect(result.reason).toBe('Reputation score improved below blocking threshold');
      expect(service.unblockIP).toHaveBeenCalledWith(mockIP);
    });
  });

  describe('queryReputations', () => {
    it('should query reputations with filters', async () => {
      const options: ReputationQueryOptions = {
        minScore: 50,
        maxScore: 200,
        riskLevel: ['MEDIUM', 'HIGH'],
        blockedOnly: false,
        daysBack: 7,
      };

      prismaService.event.findMany.mockResolvedValue([
        { ipAddress: '192.168.1.1' },
        { ipAddress: '192.168.1.2' },
      ]);

      jest.spyOn(service, 'getReputation')
        .mockResolvedValueOnce({ ...mockReputationScore, score: 100, riskLevel: 'MEDIUM' })
        .mockResolvedValueOnce({ ...mockReputationScore, score: 25, riskLevel: 'LOW' });

      const results = await service.queryReputations(options);

      expect(results).toHaveLength(1);
      expect(results[0].score).toBe(100);
      expect(results[0].riskLevel).toBe('MEDIUM');
      expect(prismaService.event.findMany).toHaveBeenCalledWith({
        where: {
          ipAddress: { not: null },
          createdAt: { gte: expect.any(Date) },
        },
        select: { ipAddress: true },
        distinct: ['ipAddress'],
        take: 1000,
      });
    });

    it('should return empty array when no IPs match criteria', async () => {
      prismaService.event.findMany.mockResolvedValue([]);
      
      const results = await service.queryReputations();
      
      expect(results).toEqual([]);
    });
  });

  describe('resetReputation', () => {
    it('should clear cache and log reset event', async () => {
      jest.spyOn(service as any, 'clearCachedReputation').mockResolvedValue(undefined);
      
      await service.resetReputation(mockIP);

      expect(service['clearCachedReputation']).toHaveBeenCalledWith(mockIP);
      expect(eventLogService.logEvent).toHaveBeenCalledWith('INTERNAL_ERROR', {
        ipAddress: mockIP,
        metadata: { reason: 'REPUTATION_RESET' },
        severity: 'INFO',
      });
    });
  });
});