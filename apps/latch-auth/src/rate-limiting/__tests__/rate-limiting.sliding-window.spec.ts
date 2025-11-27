// rate-limiting.sliding-window.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { RateLimitingService } from '../rate-limiting.service';
import { PrismaService } from '@/prisma/prisma.service';
import { EventLogService } from '@/events/event.service';
import { RedisService } from '@/redis/redis.service';
import { RateLimitConfig } from '../types/rate-limit.types';

describe('RateLimitingService - Sliding Window Algorithm', () => {
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

  describe('Sliding Window Rate Limiting', () => {
    const config: RateLimitConfig = {
      limit: 3,
      windowMs: 60000, // 1 minute
      type: 'sliding',
    };

    it('should allow first request', async () => {
      const key = 'test-key';
      const now = Date.now();
      
      redisService.lrange.mockResolvedValue([]);
    
      const result = await (service as any).checkSlidingWindowRateLimit(key, config);
    
      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(2);
      expect(redisService.lpush).toHaveBeenCalledWith(
        expect.stringContaining(':sliding'),
        expect.any(String) // Accept any string timestamp
      );
      expect(redisService.ltrim).toHaveBeenCalledWith(
        expect.stringContaining(':sliding'),
        0,
        2 // config.limit - 1
      );
    });
    
    it('should allow requests within limit', async () => {
      const key = 'test-key';
      const now = Date.now();
      // Only 2 existing requests (less than limit of 3)
      const validTimestamps = [
        (now - 10000).toString(), // 10 seconds ago
        (now - 20000).toString(), // 20 seconds ago
      ];
      
      redisService.lrange.mockResolvedValue(validTimestamps);
    
      const result = await (service as any).checkSlidingWindowRateLimit(key, config);
    
      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(0); // 3 limit - 2 existing - 1 new = 0
    });
    
    it('should reject requests exceeding limit', async () => {
      const key = 'test-key';
      const now = Date.now();
      // 3 existing requests (equals limit of 3)
      const validTimestamps = [
        (now - 5000).toString(),   // 5 seconds ago
        (now - 10000).toString(),  // 10 seconds ago
        (now - 15000).toString(),  // 15 seconds ago
      ];
      
      redisService.lrange.mockResolvedValue(validTimestamps);
    
      const result = await (service as any).checkSlidingWindowRateLimit(key, config);
    
      expect(result.allowed).toBe(false);
      expect(result.remaining).toBe(0);
      expect(result.retryAfter).toBeGreaterThan(0);
    });

    it('should reject requests exceeding limit', async () => {
      const key = 'test-key';
      const now = Date.now();
      const validTimestamps = [
        (now - 5000).toString(),   // 5 seconds ago
        (now - 10000).toString(),  // 10 seconds ago
        (now - 15000).toString(),  // 15 seconds ago
        (now - 20000).toString(),  // 20 seconds ago
      ];
      
      redisService.lrange.mockResolvedValue(validTimestamps);

      const result = await (service as any).checkSlidingWindowRateLimit(key, config);

      expect(result.allowed).toBe(false);
      expect(result.remaining).toBe(0);
      expect(result.retryAfter).toBeGreaterThan(0);
    });

    it('should handle expired timestamps', async () => {
      const key = 'test-key';
      const now = Date.now();
      const expiredTimestamp = (now - 120000).toString(); // 2 minutes ago (expired)
      const validTimestamps = [
        expiredTimestamp,
        (now - 10000).toString(), // 10 seconds ago (valid)
      ];
      
      redisService.lrange.mockResolvedValue([expiredTimestamp, (now - 10000).toString()]);

      const result = await (service as any).checkSlidingWindowRateLimit(key, config);

      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(1); // Only 1 valid request counted
    });
  });
});