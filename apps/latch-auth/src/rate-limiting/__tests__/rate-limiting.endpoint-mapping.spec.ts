// rate-limiting.endpoint-mapping.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { RateLimitingService } from '../rate-limiting.service';
import { PrismaService } from '@/prisma/prisma.service';
import { EventLogService } from '@/events/event.service';
import { RedisService } from '@/redis/redis.service';
import { TenantRateLimitProfile } from '../types/rate-limit.types';

describe('RateLimitingService - Endpoint Mapping', () => {
  let service: RateLimitingService;

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
  });

  describe('Endpoint to Rate Limit Mapping', () => {
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

    it('should map exact endpoint matches', () => {
      const config = (service as any).getRateLimitConfig(mockProfile, '/auth/otp/request');
      expect(config).toEqual(mockProfile.limits.otpRequest);
    });

    it('should map API endpoints', () => {
      const config = (service as any).getRateLimitConfig(mockProfile, '/api/users/profile');
      expect(config).toEqual(mockProfile.limits.apiRequests);
    });

    it('should map upload endpoints', () => {
      const config = (service as any).getRateLimitConfig(mockProfile, '/upload/files');
      expect(config).toEqual(mockProfile.limits.fileUploads);
    });

    it('should return undefined for unmapped endpoints', () => {
      const config = (service as any).getRateLimitConfig(mockProfile, '/unknown/endpoint');
      expect(config).toBeUndefined();
    });

    it('should handle partial matches for specific endpoints', () => {
      const config = (service as any).getRateLimitConfig(mockProfile, '/auth/otp/verify');
      expect(config).toEqual(mockProfile.limits.otpVerify);
    });
  });
});