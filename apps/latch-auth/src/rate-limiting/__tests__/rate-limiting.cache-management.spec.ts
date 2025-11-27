// rate-limiting.cache-management.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { RateLimitingService } from '../rate-limiting.service';
import { PrismaService } from '@/prisma/prisma.service';
import { EventLogService } from '@/events/event.service';
import { RedisService } from '@/redis/redis.service';
import { TenantRateLimitProfile } from '../types/rate-limit.types';

describe('RateLimitingService - Cache Management', () => {
  let service: RateLimitingService;
  let prismaService: jest.Mocked<PrismaService>;
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
              create: jest.fn(),
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
    redisService = module.get(RedisService);

    jest.clearAllMocks();
  });

  describe('Cache Operations', () => {
    it('should ensure default profiles exist', async () => {
      prismaService.tenantRateLimitProfile.findFirst.mockResolvedValue(null);
      prismaService.tenantRateLimitProfile.create.mockResolvedValue({
        id: 'default-standard-uuid',
        tenantId: 'default',
        name: 'standard',
        limits: { otpRequest: { limit: 3, windowMs: 300000, type: 'fixed' } },
        createdAt: new Date(),
        updatedAt: new Date(),
        isActive: true,
      } as any);

      await (service as any).ensureDefaultProfiles();

      expect(prismaService.tenantRateLimitProfile.create).toHaveBeenCalledTimes(2);
    });

    it('should not create duplicate default profiles', async () => {
      prismaService.tenantRateLimitProfile.findFirst.mockResolvedValue({
        id: 'existing-profile',
        tenantId: 'default',
        name: 'standard',
        limits: { otpRequest: { limit: 3, windowMs: 300000, type: 'fixed' } },
        createdAt: new Date(),
        updatedAt: new Date(),
        isActive: true,
      } as any);

      await (service as any).ensureDefaultProfiles();

      expect(prismaService.tenantRateLimitProfile.create).not.toHaveBeenCalled();
    });

    it('should warm up cache with existing profiles', async () => {
      const mockProfiles = [
        {
          id: 'profile-1',
          tenantId: 'tenant-1',
          name: 'standard',
          limits: { otpRequest: { limit: 3, windowMs: 300000, type: 'fixed' } },
          createdAt: new Date(),
          updatedAt: new Date(),
          isActive: true,
        },
      ];

      prismaService.tenantRateLimitProfile.findMany.mockResolvedValue(mockProfiles as any);

      await (service as any).warmupCache();

      expect(redisService.setex).toHaveBeenCalledWith(
        'rate-limit:tenant-1',
        600,
        expect.any(String)
      );
    });

    it('should handle cache warming errors gracefully', async () => {
      prismaService.tenantRateLimitProfile.findMany.mockRejectedValue(new Error('DB error'));

      await expect((service as any).warmupCache()).resolves.not.toThrow();
    });

    it('should cache profiles after creation', async () => {
      const profileData = {
        name: 'custom',
        limits: { otpRequest: { limit: 5, windowMs: 300000, type: 'fixed' } },
        isActive: true,
      };

      prismaService.tenantRateLimitProfile.findFirst.mockResolvedValue(null);
      prismaService.tenantRateLimitProfile.create.mockResolvedValue({
        id: 'custom-profile-123',
        tenantId: 'tenant-123',
        ...profileData,
        createdAt: new Date(),
        updatedAt: new Date(),
      } as any);

      await service.createOrUpdateTenantProfile('tenant-123', profileData);

      expect(redisService.setex).toHaveBeenCalledWith(
        'rate-limit:tenant-123',
        600,
        expect.any(String)
      );
    });
  });
});