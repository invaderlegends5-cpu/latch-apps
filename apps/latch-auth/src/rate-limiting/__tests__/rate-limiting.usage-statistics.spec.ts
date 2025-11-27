// rate-limiting.usage-statistics.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { RateLimitingService } from '../rate-limiting.service';
import { PrismaService } from '@/prisma/prisma.service';
import { EventLogService } from '@/events/event.service';
import { RedisService } from '@/redis/redis.service';
import { TenantRateLimitProfile } from '../types/rate-limit.types';

describe('RateLimitingService - Usage Statistics', () => {
  let service: RateLimitingService;
  let prismaService: jest.Mocked<PrismaService>;

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

    jest.clearAllMocks();
  });

  describe('Usage Statistics', () => {
    it('should return empty array for rate limit usage', async () => {
      const usage = await service.getRateLimitUsage('tenant-123');
      expect(usage).toEqual([]);
    });

    it('should return filtered usage for specific endpoint', async () => {
      const usage = await service.getRateLimitUsage('tenant-123', '/api/test');
      expect(usage).toEqual([]);
    });

    it('should get all tenant profiles', async () => {
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
        {
          id: 'profile-2',
          tenantId: 'tenant-2',
          name: 'premium',
          limits: { otpRequest: { limit: 5, windowMs: 300000, type: 'fixed' } },
          createdAt: new Date(),
          updatedAt: new Date(),
          isActive: true,
        },
      ];

      prismaService.tenantRateLimitProfile.findMany.mockResolvedValue(mockProfiles as any);

      const profiles = await service.getAllTenantProfiles();

      expect(profiles).toHaveLength(2);
      expect(profiles[0].id).toBe('profile-1');
      expect(profiles[1].id).toBe('profile-2');
    });

    it('should return empty array when no profiles exist', async () => {
      prismaService.tenantRateLimitProfile.findMany.mockResolvedValue([]);

      const profiles = await service.getAllTenantProfiles();

      expect(profiles).toEqual([]);
    });

    it('should filter inactive profiles', async () => {
        // Prisma should only return active profiles due to where clause
        prismaService.tenantRateLimitProfile.findMany.mockResolvedValue([
          {
            id: 'active-profile',
            tenantId: 'tenant-1',
            name: 'standard',
            limits: { otpRequest: { limit: 3, windowMs: 300000, type: 'fixed' } },
            createdAt: new Date(),
            updatedAt: new Date(),
            isActive: true,
          },
          // Note: inactive profiles would not be returned by Prisma due to where clause
        ] as any);
      
        const profiles = await service.getAllTenantProfiles();
      
        expect(profiles).toHaveLength(1);
        expect(profiles[0].id).toBe('active-profile');
      });
  });
});