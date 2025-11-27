//admin.controller.unit.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { Request } from 'express';
import { AdminController } from '../admin.controller';
import { AdminService } from '../admin.service';
import { EventLogService } from '../../events/event.service';
import { BadRequestException, NotFoundException } from '@nestjs/common';
import { UserRoleOperation } from '../dto/update-user-role.dto';
import { PrismaService } from '@/prisma/prisma.service';
import { Reflector } from '@nestjs/core';
import { RateLimitingService } from '@/rate-limiting/rate-limiting.service';
import { IPReputationService } from '@/ip-reputation/ip-reputation.service';
// Mock request object
const mockRequest = (user?: any, ip?: string, headers?: any) => ({
  user,
  ip: ip || '127.0.0.1',
  headers: headers || { 'user-agent': 'test-agent' },
} as Request);

const mockPrismaService = {
    user: {
      findUnique: jest.fn(),
      findMany: jest.fn(),
    },
    role: {
      findUnique: jest.fn(),
      findMany: jest.fn(),
    },
    // Add other models as needed by your RolesGuard
  };
  
  // Mock RateLimitingService
const mockRateLimitingService = {
  isRequestAllowed: jest.fn().mockResolvedValue({ allowed: true, remaining: -1, resetTime: new Date() }),
  // Add other methods as needed by TenantGuard
};

// Mock IPReputationService
const mockIPReputationService = {
  isIPBlocked: jest.fn().mockResolvedValue(false),
  // Add other methods as needed by your guards
};

describe('AdminController', () => {
    let controller: AdminController;
    let adminService: AdminService;
    let eventLogService: EventLogService;
  
    beforeEach(async () => {
      const module: TestingModule = await Test.createTestingModule({
        controllers: [AdminController],
        providers: [
            {
                provide: PrismaService,
                useValue: mockPrismaService,
              },
          {
            provide: AdminService,
            useValue: {
              findAllUsers: jest.fn(),
              updateUserRole: jest.fn(),
              getAuditEvents: jest.fn(),
              getRoleAnalytics: jest.fn(),
              getTenantUserStats: jest.fn(),
              bulkUpdateUserRoles: jest.fn(),
              getUserRoleDetails: jest.fn(),
            },
          },
          {
            provide: EventLogService,
            useValue: {
              logEvent: jest.fn(),
            },
          },
          {
            provide: RateLimitingService, 
            useValue: mockRateLimitingService,
          },
          {
            provide: IPReputationService, 
            useValue: mockIPReputationService,
          },
          {
            provide: 'PrismaService', // or PrismaService if it's properly imported
            useValue: mockPrismaService,
          },
          {
            provide: Reflector,
            useValue: {
              getAllAndOverride: jest.fn(), // Mock any Reflector methods used by RolesGuard
            },
          },
        ],
      }).compile();
  
      controller = module.get<AdminController>(AdminController);
      adminService = module.get<AdminService>(AdminService);
      eventLogService = module.get<EventLogService>(EventLogService);
    });
  
    it('should be defined', () => {
      expect(controller).toBeDefined();
    });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('findAllUsers', () => {
    it('should call service with correct parameters', async () => {
      const mockRequestObj = mockRequest({ sub: 'user-id', tenantId: 'tenant-id' });
      const mockResult = { data: [], meta: { total: 0, limit: 50, offset: 0, hasNext: false } };
      
      jest.spyOn(adminService, 'findAllUsers').mockResolvedValue(mockResult);
      
      const result = await controller.findAllUsers(
        mockRequestObj,
        50,
        0,
        'tenant-id',
        'true',
        'search-term',
        'active'
      );
      
      expect(adminService.findAllUsers).toHaveBeenCalledWith(
        50,
        0,
        'tenant-id',
        true,
        'search-term',
        'active'
      );
      expect(eventLogService.logEvent).toHaveBeenCalledWith('USER_LIST_ACCESSED', expect.any(Object));
      expect(result).toEqual(mockResult);
    });

    it('should throw BadRequestException for invalid limit', async () => {
      const mockRequestObj = mockRequest({ sub: 'user-id', tenantId: 'tenant-id' });
      
      await expect(controller.findAllUsers(
        mockRequestObj,
        150,
        0,
        'tenant-id',
        'true',
        'search-term',
        'active'
      )).rejects.toThrow(BadRequestException);
      
      expect(eventLogService.logEvent).toHaveBeenCalledWith('ADMIN_VALIDATION_ERROR', expect.any(Object));
    });

    it('should throw BadRequestException for invalid offset', async () => {
      const mockRequestObj = mockRequest({ sub: 'user-id', tenantId: 'tenant-id' });
      
      await expect(controller.findAllUsers(
        mockRequestObj,
        50,
        -1,
        'tenant-id',
        'true',
        'search-term',
        'active'
      )).rejects.toThrow(BadRequestException);
      
      expect(eventLogService.logEvent).toHaveBeenCalledWith('ADMIN_VALIDATION_ERROR', expect.any(Object));
    });
  });

  describe('updateUserRole', () => {
    it('should call service with correct parameters', async () => {
      const mockRequestObj = mockRequest({ sub: 'user-id', tenantId: 'tenant-id' });
      const updateUserRoleDto = {
        userId: 'user-id',
        tenantId: 'tenant-id',
        operation: UserRoleOperation.ASSIGN,
        roles: [{ roleId: 'role-id' }],
      };
      
      const mockResult = { message: 'Roles assigned successfully' };
      jest.spyOn(adminService, 'updateUserRole').mockResolvedValue(mockResult);
      
      const result = await controller.updateUserRole(updateUserRoleDto, mockRequestObj);
      
      expect(adminService.updateUserRole).toHaveBeenCalledWith(updateUserRoleDto, 'user-id');
      expect(eventLogService.logEvent).toHaveBeenCalledWith('USER_PROFILE_UPDATE', expect.any(Object));
      expect(result).toEqual(mockResult);
    });

    it('should log pre-validation event', async () => {
      const mockRequestObj = mockRequest({ sub: 'user-id', tenantId: 'tenant-id' });
      const updateUserRoleDto = {
        userId: 'user-id',
        tenantId: 'tenant-id',
        operation: UserRoleOperation.ASSIGN,
        roles: [{ roleId: 'role-id' }],
      };
      
      const mockResult = { message: 'Roles assigned successfully' };
      jest.spyOn(adminService, 'updateUserRole').mockResolvedValue(mockResult);
      
      await controller.updateUserRole(updateUserRoleDto, mockRequestObj);
      
      expect(eventLogService.logEvent).toHaveBeenCalledWith('USER_PROFILE_UPDATE', expect.objectContaining({
        metadata: expect.objectContaining({
          action: 'UPDATE_USER_ROLE_ATTEMPT'
        })
      }));
    });
  }); // Only one closing brace here, not two!

  describe('getAuditEvents', () => {
    it('should call service with correct parameters', async () => {
      const mockRequestObj = mockRequest({ sub: 'user-id', tenantId: 'tenant-id' });
      const mockResult = { data: [], meta: { total: 0, limit: 50, offset: 0, hasNext: false } };
      
      jest.spyOn(adminService, 'getAuditEvents').mockResolvedValue(mockResult);
      
      const result = await controller.getAuditEvents(
        mockRequestObj,
        50,
        0,
        'USER_PROFILE_UPDATE',
        'user-id',
        '2023-01-01T00:00:00Z',
        '2023-12-31T23:59:59Z',
        'SECURITY',
        'tenant-id'
      );
      
      expect(adminService.getAuditEvents).toHaveBeenCalledWith(
        50,
        0,
        'USER_PROFILE_UPDATE',
        'user-id',
        new Date('2023-01-01T00:00:00Z'),
        new Date('2023-12-31T23:59:59Z'),
        'SECURITY',
        'tenant-id'
      );
      expect(eventLogService.logEvent).toHaveBeenCalledWith('AUDIT_TRAIL_ACCESSED', expect.any(Object));
      expect(result).toEqual(mockResult);
    });

    it('should throw BadRequestException for invalid date format', async () => {
      const mockRequestObj = mockRequest({ sub: 'user-id', tenantId: 'tenant-id' });
      
      await expect(controller.getAuditEvents(
        mockRequestObj,
        50,
        0,
        'USER_PROFILE_UPDATE',
        'user-id',
        'invalid-date',
        '2023-12-31T23:59:59Z',
        'SECURITY',
        'tenant-id'
      )).rejects.toThrow(BadRequestException);
      
      expect(eventLogService.logEvent).toHaveBeenCalledWith('ADMIN_VALIDATION_ERROR', expect.any(Object));
    });
  });

  describe('getRoleAnalytics', () => {
    it('should call service with correct parameters', async () => {
      const mockRequestObj = mockRequest({ sub: 'user-id', tenantId: 'tenant-id' });
      const mockResult = { roleDistribution: [], userRoleStats: { _count: { id: 0 } }, permissionStats: { _count: { id: 0 } }, timestamp: new Date() };
      
      jest.spyOn(adminService, 'getRoleAnalytics').mockResolvedValue(mockResult);
      
      const result = await controller.getRoleAnalytics('tenant-id', mockRequestObj);
      
      expect(adminService.getRoleAnalytics).toHaveBeenCalledWith('tenant-id');
      expect(eventLogService.logEvent).toHaveBeenCalledWith('AUDIT_TRAIL_ACCESSED', expect.any(Object));
      expect(result).toEqual(mockResult);
    });
  });

  describe('getTenantUserStats', () => {
    it('should call service with correct parameters', async () => {
      const mockRequestObj = mockRequest({ sub: 'user-id', tenantId: 'tenant-id' });
      const mockResult = { totalUsers: 0, activeUsers: 0, roleDistribution: [], securityEventsLast30Days: 0, timestamp: new Date() };
      
      jest.spyOn(adminService, 'getTenantUserStats').mockResolvedValue(mockResult);
      
      const result = await controller.getTenantUserStats('tenant-id', mockRequestObj);
      
      expect(adminService.getTenantUserStats).toHaveBeenCalledWith('tenant-id');
      expect(eventLogService.logEvent).toHaveBeenCalledWith('AUDIT_TRAIL_ACCESSED', expect.any(Object));
      expect(result).toEqual(mockResult);
    });
  });

  describe('bulkUpdateUserRoles', () => {
    it('should call service with correct parameters', async () => {
      const mockRequestObj = mockRequest({ sub: 'user-id', tenantId: 'tenant-id' });
      const mockResult = { totalUsers: 1, successfulUpdates: 1, failedUpdates: 0, results: [] };
      
      jest.spyOn(adminService, 'bulkUpdateUserRoles').mockResolvedValue(mockResult);
      
      const result = await controller.bulkUpdateUserRoles(
        mockRequestObj,
        ['user-id'],
        ['role-id'],
        'ASSIGN',
        'reason'
      );
      
      expect(adminService.bulkUpdateUserRoles).toHaveBeenCalledWith(
        ['user-id'],
        ['role-id'],
        'ASSIGN',
        'user-id',
        'reason'
      );
      expect(eventLogService.logEvent).toHaveBeenCalledWith('USER_PROFILE_UPDATE', expect.any(Object));
      expect(result).toEqual(mockResult);
    });

    it('should throw BadRequestException for empty userIds array', async () => {
      const mockRequestObj = mockRequest({ sub: 'user-id', tenantId: 'tenant-id' });
      
      await expect(controller.bulkUpdateUserRoles(
        mockRequestObj,
        [],
        ['role-id'],
        'ASSIGN',
        'reason'
      )).rejects.toThrow(BadRequestException);
      
      expect(eventLogService.logEvent).toHaveBeenCalledWith('ADMIN_VALIDATION_ERROR', expect.any(Object));
    });

    it('should throw BadRequestException for invalid operation', async () => {
      const mockRequestObj = mockRequest({ sub: 'user-id', tenantId: 'tenant-id' });
      
      await expect(controller.bulkUpdateUserRoles(
        mockRequestObj,
        ['user-id'],
        ['role-id'],
        'INVALID_OPERATION' as any,
        'reason'
      )).rejects.toThrow(BadRequestException);
      
      expect(eventLogService.logEvent).toHaveBeenCalledWith('ADMIN_VALIDATION_ERROR', expect.any(Object));
    });
  });

  describe('getUserRoleDetails', () => {
    it('should call service with correct parameters', async () => {
      const mockRequestObj = mockRequest({ sub: 'user-id', tenantId: 'tenant-id' });
      const mockResult = { userId: 'user-id', name: 'Test User', email: 'test@example.com', roles: [] };
      
      jest.spyOn(adminService, 'getUserRoleDetails').mockResolvedValue(mockResult);
      
      const result = await controller.getUserRoleDetails('user-id', mockRequestObj);
      
      expect(adminService.getUserRoleDetails).toHaveBeenCalledWith('user-id');
      expect(eventLogService.logEvent).toHaveBeenCalledWith('USER_DATA_ACCESSED', expect.any(Object));
      expect(result).toEqual(mockResult);
    });
  });
});