// rate-limiting.fixed-window.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { RateLimitingService } from '../rate-limiting.service';
import { PrismaService } from '@/prisma/prisma.service';
import { EventLogService } from '@/events/event.service';
import { RedisService } from '@/redis/redis.service';
import { RateLimitConfig } from '../types/rate-limit.types';

describe('RateLimitingService - Fixed Window Algorithm', () => {
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

  describe('Fixed Window Rate Limiting', () => {
    const config: RateLimitConfig = {
      limit: 3,
      windowMs: 60000, // 1 minute
      type: 'fixed',
    };

    it('should allow first request in new window', async () => {
      const key = 'test-key';
      
      redisService.get.mockResolvedValueOnce(null); // No window start
      redisService.get.mockResolvedValueOnce(null); // No count

      const result = await (service as any).checkFixedWindowRateLimit(key, config);

      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(2);
      expect(redisService.setex).toHaveBeenCalledTimes(2);
    });

    it('should allow requests within limit', async () => {
      const key = 'test-key';
      const now = Date.now();
      const windowStart = now - 30000; // 30 seconds ago

      redisService.get.mockResolvedValueOnce(windowStart.toString()); // Window start
      redisService.get.mockResolvedValueOnce('2'); // Current count

      const result = await (service as any).checkFixedWindowRateLimit(key, config);

      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(0);
      expect(redisService.incr).toHaveBeenCalled();
    });

    it('should reject requests exceeding limit', async () => {
      const key = 'test-key';
      const now = Date.now();
      const windowStart = now - 30000; // 30 seconds ago

      redisService.get.mockResolvedValueOnce(windowStart.toString()); // Window start
      redisService.get.mockResolvedValueOnce('3'); // At limit

      const result = await (service as any).checkFixedWindowRateLimit(key, config);

      expect(result.allowed).toBe(false);
      expect(result.remaining).toBe(0);
      expect(result.retryAfter).toBeGreaterThan(0);
      expect(redisService.incr).toHaveBeenCalled(); // Still increments to track over-limit
    });

    it('should reset window after expiration', async () => {
      const key = 'test-key';
      const now = Date.now();
      const expiredWindowStart = now - 120000; // 2 minutes ago (window expired)

      redisService.get.mockResolvedValueOnce(expiredWindowStart.toString()); // Expired window start
      redisService.get.mockResolvedValueOnce('5'); // Old count

      const result = await (service as any).checkFixedWindowRateLimit(key, config);

      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(2);
      expect(redisService.setex).toHaveBeenCalledWith(
        expect.stringContaining(':fixed:start'),
        expect.any(Number),
        expect.any(String)
      );
    });
  });

  describe('Rate Limit Key Generation', () => {
    it('should generate correct rate limit key with user ID', () => {
      const key = (service as any).generateRateLimitKey(
        'tenant-123',
        '/api/test',
        '192.168.1.1',
        'user-456'
      );

      expect(key).toBe('rate-limit:tenant-123:/api/test:192.168.1.1:user-456');
    });

    it('should generate correct rate limit key without user ID', () => {
      const key = (service as any).generateRateLimitKey(
        'tenant-123',
        '/api/test',
        '192.168.1.1'
      );

      expect(key).toBe('rate-limit:tenant-123:/api/test:192.168.1.1');
    });
  });
});