// src/tenants/__tests__/tenants.stats.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { PrismaService } from '../../prisma/prisma.service';
import { EventLogService } from '../../events/event.service';
import { TenantsService } from '../tenants.service';
import { TenantStatusEnum } from '../dto/create-tenant.dto';
import { NotFoundException } from '@nestjs/common';
import { mockDeep, DeepMockProxy } from 'jest-mock-extended'; // Or your chosen mocking library
import { Redis } from 'ioredis';

// Define types for clarity if not already exported from the service
type TenantStatsResult = {
  userCount: number;
  sessionCount: number;
  roleCount: number;
  permissionCount: number;
  eventCount: number;
  securityEventCount: number;
};

const mockTenant = {
  id: 'tenant-123',
  slug: 'acme-corp',
  name: 'Acme Corp',
  status: TenantStatusEnum.ACTIVE,
  createdAt: new Date(),
  updatedAt: new Date(),
  branding: {},
};

describe('TenantsService - getTenantStats Unit Tests', () => {
  let service: TenantsService;
  let prismaService: DeepMockProxy<PrismaService>;
  let eventLogService: DeepMockProxy<EventLogService>;
  let redisService: jest.Mocked<Redis>;

  const mockStatsResult: TenantStatsResult = {
    userCount: 10,
    sessionCount: 5,
    roleCount: 3,
    permissionCount: 7,
    eventCount: 100,
    securityEventCount: 5,
  };

  beforeEach(async () => {
    const mockPrisma = mockDeep<PrismaService>();
    const mockEventLog = mockDeep<EventLogService>();
    const mockRedis = {
      get: jest.fn(),
      setex: jest.fn(),
      del: jest.fn(),
    } as unknown as jest.Mocked<Redis>;

    const moduleRef: TestingModule = await Test.createTestingModule({
      providers: [
        TenantsService,
        {
          provide: PrismaService,
          useValue: mockPrisma,
        },
        {
          provide: EventLogService,
          useValue: mockEventLog,
        },
        {
          provide: 'REDIS',
          useValue: mockRedis,
        },
      ],
    }).compile();

    service = moduleRef.get<TenantsService>(TenantsService);
    prismaService = moduleRef.get(PrismaService) as DeepMockProxy<PrismaService>;
    eventLogService = moduleRef.get(EventLogService) as DeepMockProxy<EventLogService>;
    redisService = moduleRef.get('REDIS') as jest.Mocked<Redis>;

    jest.clearAllMocks();
  });

  describe('getTenantStats', () => {
    it('should call Prisma to find tenant existence, then fetch all counts, return aggregated stats, and cache the result', async () => {
      // Arrange
      const slug = 'acme-corp';
    
      // Mock Prisma to find the tenant (for existence check)
      (prismaService.tenant.findUnique as jest.Mock).mockResolvedValue({
        id: mockTenant.id,
        slug: mockTenant.slug,
      });
    
      // Mock all the count methods with their expected return values
      (prismaService.user.count as jest.Mock).mockResolvedValue(mockStatsResult.userCount);
      (prismaService.session.count as jest.Mock).mockResolvedValue(mockStatsResult.sessionCount);
      (prismaService.role.count as jest.Mock).mockResolvedValue(mockStatsResult.roleCount);
      (prismaService.permission.count as jest.Mock).mockResolvedValue(mockStatsResult.permissionCount);
      // Mock the two different event count calls separately
      (prismaService.event.count as jest.Mock)
        .mockResolvedValueOnce(mockStatsResult.eventCount) // First call: total events
        .mockResolvedValueOnce(mockStatsResult.securityEventCount); // Second call: security events only
    
      const expectedCacheKey = `tenant:${slug}:stats`;
      redisService.get.mockResolvedValue(null); // Simulate cache miss
    
      // Log the state of mocks before calling the service
      console.log('Before calling service - redisService.get calls:', (redisService.get as jest.Mock).mock.calls.length);
      console.log('Before calling service - prisma tenant find calls:', (prismaService.tenant.findUnique as jest.Mock).mock.calls.length);
    
      // Act
      let result;
      try {
        result = await service.getTenantStats(slug);
        console.log('Service call succeeded');
      } catch (error) {
        console.log('Service call failed with error:', error.message);
        throw error;
      }
    
      // Log the state of mocks after calling the service
      console.log('After calling service - redisService.get calls:', (redisService.get as jest.Mock).mock.calls.length);
      console.log('After calling service - redisService.setex calls:', (redisService.setex as jest.Mock).mock.calls.length);
    

      // Assert
      // 1. Tenant existence check - check for the exact parameters
      expect(prismaService.tenant.findUnique).toHaveBeenCalledWith({
        where: { slug },
        select: { id: true }, // Only fetch ID for existence check
      });

      // 2. Count queries
      expect(prismaService.user.count).toHaveBeenCalledWith({
        where: { tenantId: mockTenant.id },
      });
      expect(prismaService.session.count).toHaveBeenCalledWith({
        where: { tenantId: mockTenant.id },
      });
      expect(prismaService.role.count).toHaveBeenCalledWith({
        where: { tenantId: mockTenant.id },
      });
      expect(prismaService.permission.count).toHaveBeenCalledWith({
        where: { tenantId: mockTenant.id },
      });
      
      // Verify the two event count calls with their specific parameters
      expect(prismaService.event.count).toHaveBeenNthCalledWith(1, {
        where: { tenantId: mockTenant.id },
      });
      expect(prismaService.event.count).toHaveBeenNthCalledWith(2, {
        where: {
          tenantId: mockTenant.id,
          severity: 'SECURITY',
        },
      });

      // 3. Result
      expect(result).toEqual(mockStatsResult);

      // 4. Caching
      expect(redisService.get).toHaveBeenCalledWith(expectedCacheKey);
      expect(redisService.setex).toHaveBeenCalledWith(
        expectedCacheKey,
        expect.any(Number),
        JSON.stringify(mockStatsResult)
      );
    });

    it('should throw NotFoundException if tenant does not exist', async () => {
      // Arrange
      const slug = 'non-existent-tenant';
      (prismaService.tenant.findUnique as jest.Mock).mockResolvedValue(null);

      // Act & Assert
      await expect(service.getTenantStats(slug)).rejects.toThrow(NotFoundException);
      expect(prismaService.tenant.findUnique).toHaveBeenCalledWith({
        where: { slug },
        select: { id: true },
      });
      // Counts should not be called if tenant doesn't exist
      expect(prismaService.user.count).not.toHaveBeenCalled();
      expect(prismaService.session.count).not.toHaveBeenCalled();
      expect(prismaService.role.count).not.toHaveBeenCalled();
      expect(prismaService.permission.count).not.toHaveBeenCalled();
      expect(prismaService.event.count).not.toHaveBeenCalled();
      expect(redisService.setex).not.toHaveBeenCalled();
    });

    it('should return cached stats if available and not call Prisma counts', async () => {
      // Arrange
      const slug = 'cached-tenant';
      const cachedStatsString = JSON.stringify(mockStatsResult);
      const expectedCacheKey = `tenant:${slug}:stats`;
      redisService.get.mockResolvedValue(cachedStatsString); // Simulate cache hit
      
      // Mock tenant existence check to pass (the service likely still checks tenant exists before returning cached data)
      (prismaService.tenant.findUnique as jest.Mock).mockResolvedValue({
        id: mockTenant.id,
        slug: mockTenant.slug,
      });
    
      // Act
      const result = await service.getTenantStats(slug);
    
      // Assert
      // The tenant existence check should still happen for security reasons
      expect(prismaService.tenant.findUnique).toHaveBeenCalledWith({
        where: { slug },
        select: { id: true },
      });
      // The expensive count queries should be skipped since cache is available
      expect(prismaService.user.count).not.toHaveBeenCalled();
      expect(prismaService.session.count).not.toHaveBeenCalled();
      expect(prismaService.role.count).not.toHaveBeenCalled();
      expect(prismaService.permission.count).not.toHaveBeenCalled();
      expect(prismaService.event.count).not.toHaveBeenCalled();
      // Result should come from cache
      expect(result).toEqual(mockStatsResult);
      // Redis get should have been called
      expect(redisService.get).toHaveBeenCalledWith(expectedCacheKey);
      // Redis setex should NOT have been called since cache was hit
      expect(redisService.setex).not.toHaveBeenCalled();
    });

    // Optional: Test error handling from Prisma count calls if the service handles them specifically
    // within the getTenantStats method (e.g., logging, re-throwing as a specific exception).
    // If Prisma errors bubble up directly, this might not be necessary unless the service wraps them.
    // Example:
    // it('should handle Prisma errors during count queries gracefully', async () => { ... });
  });

  // Optional: If the service has a method to invalidate stats cache, test it here.
  // describe('invalidateStatsCache', () => { ... });

});