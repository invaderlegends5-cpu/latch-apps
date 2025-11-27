// rate-limiting.token-bucket.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { RateLimitingService } from '../rate-limiting.service';
import { PrismaService } from '@/prisma/prisma.service';
import { EventLogService } from '@/events/event.service';
import { RedisService } from '@/redis/redis.service';
import { RateLimitConfig } from '../types/rate-limit.types';

describe('RateLimitingService - Token Bucket Algorithm', () => {
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

  describe('Token Bucket Rate Limiting', () => {
    const config: RateLimitConfig = {
      limit: 3,
      windowMs: 60000, // 1 minute
      type: 'token-bucket',
    };

    it('should initialize bucket with max tokens', async () => {
      const key = 'test-key';
      
      redisService.get.mockResolvedValueOnce(null); // No last refill
      redisService.get.mockResolvedValueOnce(null); // No tokens
    
      const result = await (service as any).checkTokenBucketRateLimit(key, config);
    
      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(2); // 3 - 1 consumed
      expect(redisService.setex).toHaveBeenCalledWith(
        expect.stringContaining(':bucket:lastRefill'),
        expect.any(Number),
        expect.any(String) // Timestamp string
      );
    });

    it('should allow requests when tokens are available', async () => {
      const key = 'test-key';
      // When both Redis calls return null, the bucket gets initialized with max tokens (3)
      // After consuming 1 token, remaining should be 2 (3 - 1 = 2)
      
      // Don't set up specific mocks - let it use default initialization
      // This test verifies the behavior when starting with a fresh bucket
      redisService.get.mockResolvedValue(null); // Both calls will return null
    
      const result = await (service as any).checkTokenBucketRateLimit(key, config);
    
      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(2); // 3 max tokens - 1 consumed = 2 remaining
    });

    it('should reject requests when no tokens available', async () => {
      const key = 'test-key';
      const now = Date.now();
      const lastRefill = now.toString(); // Very recent (0 time passed)
      const tokens = '0'; // 0 tokens available
      
      redisService.get
        .mockResolvedValueOnce(lastRefill)  // Recent refill time
        .mockResolvedValueOnce(tokens);    // No tokens
    
      const result = await (service as any).checkTokenBucketRateLimit(key, config);
    
      expect(result.allowed).toBe(false);
      expect(result.remaining).toBe(0);
      expect(result.retryAfter).toBeGreaterThan(0);
    });

    it('should refill tokens based on time passed', async () => {
      const key = 'test-key';
      const now = Date.now();
      const lastRefill = now - 120000; // 2 minutes ago
      const tokens = '0'; // No tokens available
      
      redisService.get.mockResolvedValueOnce(lastRefill.toString());
      redisService.get.mockResolvedValueOnce(tokens);

      const result = await (service as any).checkTokenBucketRateLimit(key, config);

      expect(result.allowed).toBe(true); // Tokens should have been refilled
      expect(result.remaining).toBeGreaterThan(0);
    });
  });
});