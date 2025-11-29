// rate-limiting.core.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { RateLimitingService } from '../rate-limiting.service';
import { PrismaService } from '@/prisma/prisma.service';
import { EventLogService } from '@/events/event.service';
import { RedisService } from '@/redis/redis.service';
import { TenantRateLimitProfile, RateLimitCondition } from '../types/rate-limit.types';

describe('RateLimitingService - Core Functionality', () => {
  let service: RateLimitingService;
  let prismaService: jest.Mocked<PrismaService>;
  let eventLogService: jest.Mocked<EventLogService>;
  let redisService: jest.Mocked<RedisService>;
  let configService: jest.Mocked<ConfigService>;

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
              update: jest.fn(),
            },
            tenant: {
              findMany: jest.fn(),
              findUnique: jest.fn(() => Promise.resolve({
                id: 'system-tenant',
                slug: 'system-tenant',
                name: 'System Tenant',
                status: 'ACTIVE',
                branding: {},
                createdAt: new Date(),
                updatedAt: new Date()
              })),
              count: jest.fn(() => Promise.resolve(10)),
              update: jest.fn(),
              delete: jest.fn(),
              
              // This 'create' mock definition is necessary to fix the TypeError:
              create: jest.fn((args: any) => {
                return Promise.resolve({
                  id: 'new-tenant-id-' + Date.now(), 
                  name: args.data.name,
                  slug: args.data.slug,
                  status: args.data.status || 'ACTIVE',
                  branding: args.data.branding || {},
                  createdAt: new Date(),
                  updatedAt: new Date(),
                });
              }),
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
    configService = module.get(ConfigService);

    jest.clearAllMocks();
  });

  describe('Module Lifecycle', () => {
    it('should be defined', () => {
      expect(service).toBeDefined();
    });

    it('should initialize properly', async () => {
      const ensureSpy = jest.spyOn(service as any, 'ensureDefaultProfiles');
      const warmupSpy = jest.spyOn(service as any, 'warmupCache');

      await service.onModuleInit();

      expect(ensureSpy).toHaveBeenCalled();
      expect(warmupSpy).toHaveBeenCalled();
    });

    it('should handle module destruction', async () => {
      await expect(service.onModuleDestroy()).resolves.not.toThrow();
    });
  });

  describe('Rate Limit Profile Management', () => {
    it('should get tenant rate limit profile from cache', async () => {
        const mockProfile: TenantRateLimitProfile = {
          id: 'profile-123',
          tenantId: 'tenant-123',
          name: 'standard',
          limits: {
            otpRequest: { limit: 3, windowMs: 300000, type: 'fixed' },
            otpVerify: { limit: 6, windowMs: 600000, type: 'fixed' },
            refresh: { limit: 20, windowMs: 60000, type: 'fixed' },
            login: { limit: 5, windowMs: 900000, type: 'fixed' },
            apiRequests: { limit: 100, windowMs: 60000, type: 'sliding' },
            fileUploads: { limit: 10, windowMs: 3600000, type: 'fixed' },
          },
          createdAt: new Date(),
          updatedAt: new Date(),
          isActive: true,
        };
      
        // When stored in Redis and retrieved, dates become strings
        const mockProfileAsString = JSON.stringify(mockProfile);
        const expectedProfile = JSON.parse(mockProfileAsString); // This converts dates to strings
      
        redisService.get.mockResolvedValue(mockProfileAsString);
      
        const result = await service.getTenantRateLimitProfile('tenant-123');
      
        expect(result).toEqual(expectedProfile);
        expect(redisService.get).toHaveBeenCalledWith('rate-limit:tenant-123');
      });

    it('should get tenant rate limit profile from database if not in cache', async () => {
      const mockProfile = {
        id: 'profile-123',
        tenantId: 'tenant-123',
        name: 'standard',
        limits: { otpRequest: { limit: 3, windowMs: 300000, type: 'fixed' } },
        createdAt: new Date(),
        updatedAt: new Date(),
        isActive: true,
      };

      redisService.get.mockResolvedValue(null);
      prismaService.tenantRateLimitProfile.findFirst.mockResolvedValue(mockProfile as any);

      const result = await service.getTenantRateLimitProfile('tenant-123');

      expect(result).not.toBeNull();
      expect(result?.id).toBe('profile-123');
      expect(redisService.setex).toHaveBeenCalledWith(
        'rate-limit:tenant-123',
        600,
        expect.any(String)
      );
    });

    it('should return null if no profile exists', async () => {
      redisService.get.mockResolvedValue(null);
      prismaService.tenantRateLimitProfile.findFirst.mockResolvedValue(null);

      const result = await service.getTenantRateLimitProfile('non-existent-tenant');

      expect(result).toBeNull();
    });

    it('should create or update tenant profile', async () => {
      const profileData = {
        name: 'premium',
        limits: {
          otpRequest: { limit: 5, windowMs: 300000, type: 'fixed' },
        },
        isActive: true,
      };

      const mockExisting = {
        id: 'existing-profile-123',
        tenantId: 'tenant-123',
        name: 'old-name',
        limits: { otpRequest: { limit: 3, windowMs: 300000, type: 'fixed' } },
        createdAt: new Date(),
        updatedAt: new Date(),
        isActive: true,
      };

      prismaService.tenantRateLimitProfile.findFirst.mockResolvedValue(mockExisting as any);
      prismaService.tenantRateLimitProfile.update.mockResolvedValue({
        ...mockExisting,
        ...profileData,
        updatedAt: new Date(),
      } as any);

      const result = await service.createOrUpdateTenantProfile('tenant-123', profileData);

      expect(result.name).toBe('premium');
      expect(result.limits.otpRequest.limit).toBe(5);
      expect(prismaService.tenantRateLimitProfile.update).toHaveBeenCalled();
    });
  });

  describe('Rate Limit Condition Processing', () => {
    it('should extract rate limit condition from permission', async () => {
      const mockPermission = {
        conditionType: 'RATE_LIMITED',
        value: {
          endpoint: '/api/test',
          limit: 100,
          windowMs: 60000,
          algorithm: 'sliding',
        },
        description: 'API rate limit',
      };

      const result = await service.getRateLimitConditionFromPermission(mockPermission);

      expect(result).toEqual({
        conditionType: 'RATE_LIMITED',
        value: mockPermission.value,
        description: 'API rate limit',
      });
    });

    it('should return null for non-rate limit condition', async () => {
      const mockPermission = {
        conditionType: 'TIME_BASED',
        value: 'some-value',
      };

      const result = await service.getRateLimitConditionFromPermission(mockPermission);

      expect(result).toBeNull();
    });
  });
});