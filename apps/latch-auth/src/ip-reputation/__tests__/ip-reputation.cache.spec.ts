// ip-reputation.cache.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { IPReputationService } from '../ip-reputation.service';
import { RedisService } from '@/redis/redis.service';
import { PrismaService } from '@/prisma/prisma.service';
import { EventLogService } from '@/events/event.service';
import { SecurityMonitoringService } from '@/security/security-monitor.service';
import { ConfigService } from '@nestjs/config';
import { IPReputationScore } from '../types/reputation.types';

describe('IPReputationService - Cache', () => {
  let service: IPReputationService;
  let redisService: jest.Mocked<RedisService>;

  const mockIP = '192.168.1.1';
  const mockReputation: IPReputationScore = {
    ip: mockIP,
    score: 50,
    riskLevel: 'MEDIUM',
    totalEvents: 5,
    securityEvents: 1,
    lastUpdated: new Date(),
    eventCounts: {} as any,
    threatIndicators: [],
    reputationHistory: [],
    blocked: false,
    whitelisted: false,
    metadata: {},
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        IPReputationService,
        {
          provide: RedisService,
          useValue: {
            get: jest.fn(),
            setex: jest.fn(),
            del: jest.fn(),
          },
        },
        {
          provide: PrismaService,
          useValue: {},
        },
        {
          provide: EventLogService,
          useValue: {},
        },
        {
          provide: SecurityMonitoringService,
          useValue: {},
        },
        {
          provide: ConfigService,
          useValue: {},
        },
      ],
    }).compile();

    service = module.get<IPReputationService>(IPReputationService);
    redisService = module.get(RedisService);
  });

  describe('Cache operations', () => {
    it('should get reputation from Redis cache', async () => {
      redisService.get.mockResolvedValue(JSON.stringify(mockReputation));

      const result = await service['getCachedReputation'](mockIP);

      expect(result).toEqual(mockReputation);
      expect(redisService.get).toHaveBeenCalledWith('ip-reputation:192.168.1.1');
    });

    it('should return null when Redis cache miss', async () => {
      redisService.get.mockResolvedValue(null);

      const result = await service['getCachedReputation'](mockIP);

      expect(result).toBeNull();
    });

    it('should use fallback cache when Redis fails', async () => {
      redisService.get.mockRejectedValue(new Error('Redis unavailable'));

      const result = await service['getCachedReputation'](mockIP);

      expect(result).toBeNull();
    });

    it('should set reputation in Redis cache', async () => {
      redisService.setex.mockResolvedValue(undefined);

      await service['setCachedReputation'](mockReputation);

      expect(redisService.setex).toHaveBeenCalledWith(
        'ip-reputation:192.168.1.1',
        300,
        JSON.stringify(mockReputation)
      );
    });

    it('should use fallback cache when Redis set fails', async () => {
      redisService.setex.mockRejectedValue(new Error('Redis error'));

      await service['setCachedReputation'](mockReputation);

      // Fallback cache should be populated
      const fallbackKey = 'ip-reputation:192.168.1.1';
      expect(service['fallbackCache'].has(fallbackKey)).toBe(true);
    });

    it('should clear reputation from cache', async () => {
      redisService.del.mockResolvedValue(undefined);

      await service['clearCachedReputation'](mockIP);

      expect(redisService.del).toHaveBeenCalledWith('ip-reputation:192.168.1.1');
      expect(service['fallbackCache'].has('ip-reputation:192.168.1.1')).toBe(false);
    });
  });

  describe('Cache warmup', () => {
    it('should warmup cache with high-risk IPs', async () => {
      const mockHighRiskIPs = [
        { ipAddress: '192.168.1.100' },
        { ipAddress: '192.168.1.101' },
      ];

      const prismaService = {
        event: {
          findMany: jest.fn().mockResolvedValue(mockHighRiskIPs),
        },
      };

      const module: TestingModule = await Test.createTestingModule({
        providers: [
          IPReputationService,
          {
            provide: RedisService,
            useValue: redisService,
          },
          {
            provide: PrismaService,
            useValue: prismaService,
          },
          {
            provide: EventLogService,
            useValue: {},
          },
          {
            provide: SecurityMonitoringService,
            useValue: {},
          },
          {
            provide: ConfigService,
            useValue: {},
          },
        ],
      }).compile();

      const warmupService = module.get<IPReputationService>(IPReputationService);
      jest.spyOn(warmupService, 'getReputation').mockResolvedValue(mockReputation);
      jest.spyOn(warmupService as any, 'setCachedReputation').mockResolvedValue(undefined);

      await warmupService['warmupCache']();

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
      expect(warmupService.getReputation).toHaveBeenCalledTimes(2);
    });
  });
});