// rate-limiting.request-flow.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { RateLimitingService } from '../rate-limiting.service';
import { PrismaService } from '@/prisma/prisma.service';
import { EventLogService } from '@/events/event.service';
import { RedisService } from '@/redis/redis.service';
import { TenantRateLimitProfile } from '../types/rate-limit.types';

describe('RateLimitingService - Request Flow Integration', () => {
  let service: RateLimitingService;
  let prismaService: jest.Mocked<PrismaService>;
  let eventLogService: jest.Mocked<EventLogService>;
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
    prismaService = module.get(PrismaService);
    eventLogService = module.get(EventLogService);
    redisService = module.get(RedisService);

    jest.clearAllMocks();
  });

  describe('Complete Request Flow', () => {
    it('should allow request when rate limits are not exceeded', async () => {
      const mockProfile: TenantRateLimitProfile = {
        id: 'profile-123',
        tenantId: 'tenant-123',
        name: 'standard',
        limits: {
          apiRequests: { limit: 100, windowMs: 60000, type: 'sliding' },
        },
        createdAt: new Date(),
        updatedAt: new Date(),
        isActive: true,
      };

      redisService.get.mockResolvedValue(JSON.stringify(mockProfile));
      redisService.lrange.mockResolvedValue([]);

      const result = await service.isRequestAllowed(
        'tenant-123',
        '/api/test',
        '192.168.1.1',
        'user-456'
      );

      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(99);
      expect(eventLogService.logEvent).toHaveBeenCalledWith(
        'USER_LIST_ACCESSED',
        expect.objectContaining({
          userId: 'user-456',
          tenantId: 'tenant-123',
          metadata: expect.objectContaining({
            action: 'RATE_LIMIT_CHECK',
            endpoint: '/api/test',
          }),
        })
      );
    });

    it('should reject request when rate limits are exceeded', async () => {
      const mockProfile: TenantRateLimitProfile = {
        id: 'profile-123',
        tenantId: 'tenant-123',
        name: 'standard',
        limits: {
          apiRequests: { limit: 1, windowMs: 60000, type: 'fixed' },
        },
        createdAt: new Date(),
        updatedAt: new Date(),
        isActive: true,
      };

      const now = Date.now();
      redisService.get.mockResolvedValueOnce(JSON.stringify(mockProfile));
      redisService.get.mockResolvedValueOnce((now - 30000).toString()); // Window start
      redisService.get.mockResolvedValueOnce('1'); // At limit

      const result = await service.isRequestAllowed(
        'tenant-123',
        '/api/test',
        '192.168.1.1'
      );

      expect(result.allowed).toBe(false);
      expect(result.remaining).toBe(0);
      expect(eventLogService.logEvent).toHaveBeenCalledWith(
        'REFRESH_FAILED',
        expect.objectContaining({
          severity: 'SECURITY',
        })
      );
    });

    it('should handle missing tenant profile gracefully', async () => {
      redisService.get.mockResolvedValue(null);
      prismaService.tenantRateLimitProfile.findFirst.mockResolvedValue(null);

      const result = await service.isRequestAllowed(
        'non-existent-tenant',
        '/api/test',
        '192.168.1.1'
      );

      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(-1);
    });

    it('should handle missing specific endpoint limits', async () => {
      const mockProfile: TenantRateLimitProfile = {
        id: 'profile-123',
        tenantId: 'tenant-123',
        name: 'standard',
        limits: {
          apiRequests: { limit: 100, windowMs: 60000, type: 'sliding' },
        },
        createdAt: new Date(),
        updatedAt: new Date(),
        isActive: true,
      };

      redisService.get.mockResolvedValue(JSON.stringify(mockProfile));

      const result = await service.isRequestAllowed(
        'tenant-123',
        '/unknown/endpoint',
        '192.168.1.1'
      );

      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(-1);
    });

    it('should fail open on errors', async () => {
      redisService.get.mockRejectedValue(new Error('Redis error'));

      const result = await service.isRequestAllowed(
        'tenant-123',
        '/api/test',
        '192.168.1.1'
      );

      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(-1);
    });
  });
});