// rate-limiting.permission-integration.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { RateLimitingService } from '../rate-limiting.service';
import { PrismaService } from '@/prisma/prisma.service';
import { EventLogService } from '@/events/event.service';
import { RedisService } from '@/redis/redis.service';
import { RateLimitCondition } from '../types/rate-limit.types';

describe('RateLimitingService - Permission Integration', () => {
  let service: RateLimitingService;
  let redisService: jest.Mocked<RedisService>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RateLimitingService,
        {
          provide: PrismaService,
          useValue: {
            tenantRateLimitProfile: {
              findFirst: jest.fn(),
              findMany: jest.fn(),
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
          provide: RedisService,
          useValue: {
            get: jest.fn(),
            setex: jest.fn(),
            lrange: jest.fn(),
            lpush: jest.fn(),
            ltrim: jest.fn(),
            expire: jest.fn(),
            incr: jest.fn(),
          },
        },
        {
          provide: ConfigService,
          useValue: {},
        },
      ],
    }).compile();

    service = module.get<RateLimitingService>(RateLimitingService);
    redisService = module.get(RedisService);

    jest.clearAllMocks();
  });

  describe('Permission-based Rate Limiting', () => {
    it('should apply rate limits from permission conditions', async () => {
      const condition: RateLimitCondition = {
        conditionType: 'RATE_LIMITED',
        value: {
          endpoint: '/api/test',
          limit: 10,
          windowMs: 60000,
          algorithm: 'sliding',
        },
        description: 'Test rate limit',
      };

      redisService.lrange.mockResolvedValue([]);

      const result = await service.applyRateLimitFromPermission(
        'tenant-123',
        condition,
        '192.168.1.1',
        'user-456'
      );

      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(9);
    });

    it('should handle different algorithm types', async () => {
      const condition: RateLimitCondition = {
        conditionType: 'RATE_LIMITED',
        value: {
          endpoint: '/api/test',
          limit: 5,
          windowMs: 60000,
          algorithm: 'fixed',
        },
        description: 'Fixed window rate limit',
      };

      redisService.get.mockResolvedValueOnce(null); // No window start
      redisService.get.mockResolvedValueOnce(null); // No count

      const result = await service.applyRateLimitFromPermission(
        'tenant-123',
        condition,
        '192.168.1.1'
      );

      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(4);
    });

    it('should handle token bucket algorithm from permissions', async () => {
      const condition: RateLimitCondition = {
        conditionType: 'RATE_LIMITED',
        value: {
          endpoint: '/api/test',
          limit: 3,
          windowMs: 60000,
          algorithm: 'token-bucket',
        },
        description: 'Token bucket rate limit',
      };

      redisService.get.mockResolvedValueOnce(null); // No last refill
      redisService.get.mockResolvedValueOnce(null); // No tokens

      const result = await service.applyRateLimitFromPermission(
        'tenant-123',
        condition,
        '192.168.1.1'
      );

      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(2);
    });

    it('should handle unknown algorithm types', async () => {
      const condition: RateLimitCondition = {
        conditionType: 'RATE_LIMITED',
        value: {
          endpoint: '/api/test',
          limit: 10,
          windowMs: 60000,
          algorithm: 'unknown-algorithm' as any,
        },
        description: 'Unknown algorithm',
      };

      const result = await service.applyRateLimitFromPermission(
        'tenant-123',
        condition,
        '192.168.1.1'
      );

      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(-1);
    });
  });
});