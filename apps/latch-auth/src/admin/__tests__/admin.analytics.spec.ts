// admin.analytics.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException, NotFoundException } from '@nestjs/common';
import { Request } from 'express';
import { AdminController } from '../admin.controller';
import { AdminService } from '../admin.service';
import { EventLogService } from '@/events/event.service';
import { TenantGuard } from '@/auth/guards/tenant.guard';
import { PrismaService } from '@/prisma/prisma.service'; // Import PrismaService
import { Redis } from 'ioredis';
import { RateLimitingService } from '@/rate-limiting/rate-limiting.service';
import { IPReputationService } from '@/ip-reputation/ip-reputation.service';

// Mock request object
const mockRequest = {
  user: { sub: 'user-id', tenantId: 'tenant-id' },
  ip: '127.0.0.1',
  headers: { 'user-agent': 'test-agent' },
} as unknown as Request; // Casting might be needed depending on exact mock requirements

describe('AdminController - Analytics', () => {
  let controller: AdminController;
  let adminService: AdminService;
  let eventLogService: EventLogService;
  let prismaService: PrismaService; // Reference for setting up mocks per test if needed

  
beforeEach(async () => {
  const module: TestingModule = await Test.createTestingModule({
    controllers: [AdminController],
    providers: [
      AdminService, // Provide AdminService so its dependencies are resolved
      {
        provide: EventLogService,
        useValue: {
          logEvent: jest.fn(), // Mock logEvent
          // Add other methods if the analytics methods use them, e.g., queryEvents
          queryEvents: jest.fn(),
        },
      },
      // ADD RateLimitingService - this is required by TenantGuard
      {
        provide: RateLimitingService,
        useValue: {
          isRequestAllowed: jest.fn().mockResolvedValue({
            allowed: true,
            remaining: -1,
            resetTime: new Date(),
            retryAfter: undefined,
          }),
          // Add other methods if TenantGuard uses them
          getRateLimitStatus: jest.fn(),
          // ... other RateLimitingService methods as needed
        },
      },
      {
        provide: IPReputationService, // ADD THIS - needed by AdminController
        useValue: {
          isIPBlocked: jest.fn().mockResolvedValue(false),
          getReputation: jest.fn().mockResolvedValue({ score: 0, riskLevel: 'LOW' }),
          // Add other methods as needed by AdminController
        },
      },
      // ADD PrismaService mock
      {
        provide: PrismaService,
        useValue: {
          // Mock the methods that AdminService.analytics calls might need
          // e.g., getRoleAnalytics uses prisma.role.groupBy, prisma.userRole.aggregate, prisma.rolePermission.aggregate
          role: {
            groupBy: jest.fn(),
            // ... other role methods if used by analytics
          },
          userRole: {
            aggregate: jest.fn(),
            findMany: jest.fn(), // Add this for TenantGuard
            // ... other userRole methods if used by analytics
          },
          rolePermission: {
            aggregate: jest.fn(),
            // ... other rolePermission methods if used by analytics
          },
          // e.g., getTenantUserStats uses prisma.tenant.findUnique, prisma.user.count, prisma.role.groupBy, prisma.event.count
          tenant: {
             findUnique: jest.fn(),
             // ... other tenant methods if used by analytics
          },
          user: {
            count: jest.fn(),
            findUnique: jest.fn(),
            // ... other user methods if used by analytics
          },
          event: {
            count: jest.fn(),
            // ... other event methods if used by analytics
          },
          // Add other Prisma models/methods as needed by the specific analytics methods tested
          // Also mock $transaction if used within analytics methods
          $transaction: jest.fn().mockImplementation(async (callback) => {
            // Define a basic transaction mock structure if analytics methods use transactions
            // This is a simplified example, adjust based on actual transaction usage in analytics
            const tx = {
              role: {
                groupBy: jest.fn(),
                // ... other methods
              },
              userRole: {
                aggregate: jest.fn(),
                // ... other methods
              },
              // ... other models as needed for the transaction
            };
            return await callback(tx);
          }),
        },
      },
      // ADD REDIS mock
      {
        provide: 'REDIS', // The token used by AdminService to inject Redis
        useValue: {
          get: jest.fn(),
          setex: jest.fn(),
          del: jest.fn(),
          // Add other methods used by AdminService if needed by the analytics endpoints
        } as Partial<Redis>, // Cast to Partial to satisfy TypeScript if not mocking everything
      },
    ],
  })
  // Ensure AdminService is correctly instantiated with its dependencies
  .compile();

  controller = module.get<AdminController>(AdminController);
  adminService = module.get<AdminService>(AdminService);
  eventLogService = module.get<EventLogService>(EventLogService);
  prismaService = module.get<PrismaService>(PrismaService); // Get reference to set up specific mocks per test if needed
});

  describe('GET /analytics/roles/:tenantId', () => {
    it('should return role analytics for a valid tenant', async () => {
      const mockTenantId = 'tenant-uuid';
      const mockAnalytics = {
        roleDistribution: [
          { name: 'admin', _count: 2, _avg: { priority: 1 } },
          { name: 'user', _count: 5, _avg: { priority: 0.5 } },
        ],
        userRoleStats: { _count: { id: 7, userId: 7, roleId: 7 } },
        permissionStats: { _count: { id: 15 } },
        timestamp: new Date(),
      };

      // Mock the AdminService method call
      jest.spyOn(adminService, 'getRoleAnalytics').mockResolvedValue(mockAnalytics);

      const result = await controller.getRoleAnalytics(mockTenantId, mockRequest);

      expect(adminService.getRoleAnalytics).toHaveBeenCalledWith(mockTenantId);
      expect(eventLogService.logEvent).toHaveBeenCalledWith('AUDIT_TRAIL_ACCESSED', {
        userId: 'user-id',
        tenantId: 'tenant-id',
        metadata: {
          action: 'GET_ROLE_ANALYTICS',
          targetTenantId: mockTenantId,
        },
        ipAddress: '127.0.0.1',
        userAgent: 'test-agent',
        severity: 'INFO',
      });
      expect(result).toEqual(mockAnalytics);
    });

    it('should throw NotFoundException when tenant does not exist', async () => {
      const mockTenantId = 'non-existent-tenant';
      const mockError = new NotFoundException('Tenant with id "non-existent-tenant" not found');

      jest.spyOn(adminService, 'getRoleAnalytics').mockRejectedValue(mockError);

      await expect(controller.getRoleAnalytics(mockTenantId, mockRequest)).rejects.toThrow(NotFoundException);
      await expect(controller.getRoleAnalytics(mockTenantId, mockRequest)).rejects.toThrow('Tenant with id "non-existent-tenant" not found');
    });

    it('should log access event when retrieving role analytics', async () => {
      const mockTenantId = 'tenant-uuid';
      const mockAnalytics = {
        roleDistribution: [],
        userRoleStats: { _count: { id: 0, userId: 0, roleId: 0 } },
        permissionStats: { _count: { id: 0 } },
        timestamp: new Date(),
      };

      jest.spyOn(adminService, 'getRoleAnalytics').mockResolvedValue(mockAnalytics);

      await controller.getRoleAnalytics(mockTenantId, mockRequest);

      expect(eventLogService.logEvent).toHaveBeenCalledWith('AUDIT_TRAIL_ACCESSED', expect.objectContaining({
        userId: 'user-id',
        tenantId: 'tenant-id',
        metadata: {
          action: 'GET_ROLE_ANALYTICS',
          targetTenantId: mockTenantId,
        },
        severity: 'INFO',
      }));
    });

    it('should handle tenantId from route parameters correctly', async () => {
      const mockTenantId = 'test-tenant-id';
      const mockAnalytics = {
        roleDistribution: [],
        userRoleStats: { _count: { id: 0, userId: 0, roleId: 0 } },
        permissionStats: { _count: { id: 0 } },
        timestamp: new Date(),
      };

      jest.spyOn(adminService, 'getRoleAnalytics').mockResolvedValue(mockAnalytics);

      const result = await controller.getRoleAnalytics(mockTenantId, mockRequest);

      expect(adminService.getRoleAnalytics).toHaveBeenCalledWith(mockTenantId);
      expect(result).toEqual(mockAnalytics);
    });
  });

  describe('GET /analytics/users/:tenantId', () => {
    it('should return user statistics for a valid tenant', async () => {
      const mockTenantId = 'tenant-uuid';
      const mockUserStats = {
        totalUsers: 10,
        activeUsers: 8,
        roleDistribution: [
          { name: 'admin', _count: 2 },
          { name: 'user', _count: 8 },
        ],
        securityEventsLast30Days: 2,
        timestamp: new Date(),
      };

      jest.spyOn(adminService, 'getTenantUserStats').mockResolvedValue(mockUserStats);

      const result = await controller.getTenantUserStats(mockTenantId, mockRequest);

      expect(adminService.getTenantUserStats).toHaveBeenCalledWith(mockTenantId);
      expect(eventLogService.logEvent).toHaveBeenCalledWith('AUDIT_TRAIL_ACCESSED', {
        userId: 'user-id',
        tenantId: 'tenant-id',
        metadata: {
          action: 'GET_TENANT_USER_STATS',
          targetTenantId: mockTenantId,
        },
        ipAddress: '127.0.0.1',
        userAgent: 'test-agent',
        severity: 'INFO',
      });
      expect(result).toEqual(mockUserStats);
    });

    it('should throw NotFoundException when tenant does not exist', async () => {
      const mockTenantId = 'non-existent-tenant';
      const mockError = new NotFoundException('Tenant with id "non-existent-tenant" not found');

      jest.spyOn(adminService, 'getTenantUserStats').mockRejectedValue(mockError);

      await expect(controller.getTenantUserStats(mockTenantId, mockRequest)).rejects.toThrow(NotFoundException);
      await expect(controller.getTenantUserStats(mockTenantId, mockRequest)).rejects.toThrow('Tenant with id "non-existent-tenant" not found');
    });

    it('should log access event when retrieving user statistics', async () => {
      const mockTenantId = 'tenant-uuid';
      const mockUserStats = {
        totalUsers: 5,
        activeUsers: 4,
        roleDistribution: [],
        securityEventsLast30Days: 0,
        timestamp: new Date(),
      };

      jest.spyOn(adminService, 'getTenantUserStats').mockResolvedValue(mockUserStats);

      await controller.getTenantUserStats(mockTenantId, mockRequest);

      expect(eventLogService.logEvent).toHaveBeenCalledWith('AUDIT_TRAIL_ACCESSED', expect.objectContaining({
        userId: 'user-id',
        tenantId: 'tenant-id',
        metadata: {
          action: 'GET_TENANT_USER_STATS',
          targetTenantId: mockTenantId,
        },
        severity: 'INFO',
      }));
    });

    it('should handle different tenantId values correctly', async () => {
      const mockTenantId = 'another-tenant-id';
      const mockUserStats = {
        totalUsers: 15,
        activeUsers: 12,
        roleDistribution: [
          { name: 'admin', _count: 1 },
          { name: 'manager', _count: 3 },
          { name: 'user', _count: 11 },
        ],
        securityEventsLast30Days: 1,
        timestamp: new Date(),
      };

      jest.spyOn(adminService, 'getTenantUserStats').mockResolvedValue(mockUserStats);

      const result = await controller.getTenantUserStats(mockTenantId, mockRequest);

      expect(adminService.getTenantUserStats).toHaveBeenCalledWith(mockTenantId);
      expect(result).toEqual(mockUserStats);
    });

    it('should handle analytics with complex role distribution', async () => {
      const mockTenantId = 'complex-tenant';
      const mockAnalytics = {
        roleDistribution: [
          { name: 'admin', _count: 2, _avg: { priority: 1 } },
          { name: 'manager', _count: 3, _avg: { priority: 0.8 } },
          { name: 'editor', _count: 5, _avg: { priority: 0.6 } },
          { name: 'viewer', _count: 10, _avg: { priority: 0.2 } },
        ],
        userRoleStats: { 
          _count: { 
            id: 20, 
            userId: 15, 
            roleId: 20 
          } 
        },
        permissionStats: { _count: { id: 50 } },
        timestamp: new Date(),
      };

      jest.spyOn(adminService, 'getRoleAnalytics').mockResolvedValue(mockAnalytics);

      const result = await controller.getRoleAnalytics(mockTenantId, mockRequest);

      expect(result).toEqual(mockAnalytics);
      expect(adminService.getRoleAnalytics).toHaveBeenCalledWith(mockTenantId);
    });

    it('should handle user stats with zero values', async () => {
      const mockTenantId = 'empty-tenant';
      const mockUserStats = {
        totalUsers: 0,
        activeUsers: 0,
        roleDistribution: [],
        securityEventsLast30Days: 0,
        timestamp: new Date(),
      };

      jest.spyOn(adminService, 'getTenantUserStats').mockResolvedValue(mockUserStats);

      const result = await controller.getTenantUserStats(mockTenantId, mockRequest);

      expect(result).toEqual(mockUserStats);
      expect(adminService.getTenantUserStats).toHaveBeenCalledWith(mockTenantId);
    });
  });

  describe('Analytics Edge Cases', () => {
    it('should handle tenantId with special characters', async () => {
      const mockTenantId = 'tenant-with-special-chars-123';
      const mockAnalytics = {
        roleDistribution: [{ name: 'admin', _count: 1, _avg: { priority: 1 } }],
        userRoleStats: { _count: { id: 1, userId: 1, roleId: 1 } },
        permissionStats: { _count: { id: 5 } },
        timestamp: new Date(),
      };

      jest.spyOn(adminService, 'getRoleAnalytics').mockResolvedValue(mockAnalytics);

      const result = await controller.getRoleAnalytics(mockTenantId, mockRequest);

      expect(result).toEqual(mockAnalytics);
      expect(adminService.getRoleAnalytics).toHaveBeenCalledWith(mockTenantId);
    });

    it('should handle tenantId with UUID format', async () => {
      const mockTenantId = 'a1b2c3d4-e5f6-7890-1234-567890abcdef';
      const mockUserStats = {
        totalUsers: 1,
        activeUsers: 1,
        roleDistribution: [{ name: 'admin', _count: 1 }],
        securityEventsLast30Days: 0,
        timestamp: new Date(),
      };

      jest.spyOn(adminService, 'getTenantUserStats').mockResolvedValue(mockUserStats);

      const result = await controller.getTenantUserStats(mockTenantId, mockRequest);

      expect(result).toEqual(mockUserStats);
      expect(adminService.getTenantUserStats).toHaveBeenCalledWith(mockTenantId);
    });

    it('should handle analytics with null values gracefully', async () => {
      const mockTenantId = 'tenant-id';
      const mockAnalytics = {
        roleDistribution: null,
        userRoleStats: null,
        permissionStats: null,
        timestamp: new Date(),
      } as any;

      jest.spyOn(adminService, 'getRoleAnalytics').mockResolvedValue(mockAnalytics);

      const result = await controller.getRoleAnalytics(mockTenantId, mockRequest);

      expect(result).toEqual(mockAnalytics);
    });
  });
});