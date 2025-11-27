//admin.bulk-operations.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException, NotFoundException } from '@nestjs/common';
import { Request } from 'express';
import { AdminController } from '../admin.controller';
import { AdminService } from '../admin.service';
import { EventLogService } from '@/events/event.service';
import { PrismaService } from '@/prisma/prisma.service'; // Import PrismaService
import { Redis } from 'ioredis'; // Import Redis type if needed for AdminService mock
import { RateLimitingService } from '@/rate-limiting/rate-limiting.service';
import { IPReputationService } from '@/ip-reputation/ip-reputation.service';

// Mock request object
const mockRequest = {
  user: { sub: 'admin-user-id', tenantId: 'tenant-id' },
  ip: '127.0.0.1',
  headers: { 'user-agent': 'test-agent' },
} as Request;

describe('AdminController - Bulk Operations', () => {
  let controller: AdminController;
  let adminService: AdminService;
  let eventLogService: EventLogService;
  let prismaService: PrismaService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AdminController],
      providers: [
        {
          provide: AdminService,
          useValue: {
            bulkUpdateUserRoles: jest.fn(),
            findAllUsers: jest.fn(),
            updateUserRole: jest.fn(),
            getAuditEvents: jest.fn(),
            getRoleAnalytics: jest.fn(),
            getTenantUserStats: jest.fn(),
            getUserRoleDetails: jest.fn(),
          },
        },
        {
          provide: EventLogService,
          useValue: {
            logEvent: jest.fn(),
            queryEvents: jest.fn(),
          },
        },
        {
          provide: PrismaService,
          useValue: {
            userRole: {
              findMany: jest.fn(),
            },
            iPBlocked: {
              findFirst: jest.fn().mockResolvedValue(null),
              findMany: jest.fn().mockResolvedValue([]),
              create: jest.fn(),
              update: jest.fn(),
              delete: jest.fn(),
              upsert: jest.fn(),
            },
            tenant: {
              findUnique: jest.fn(),
            },
            user: {
              findUnique: jest.fn(),
            },
            session: {
              findUnique: jest.fn(),
            },
            $transaction: jest.fn().mockImplementation(async (callback) => {
              const tx = {
                userRole: {
                  findMany: jest.fn(),
                },
                tenant: {
                  findUnique: jest.fn(),
                },
              };
              return await callback(tx);
            }),
          },
        },
        {
          provide: IPReputationService,
          useValue: {
            isIPBlocked: jest.fn().mockResolvedValue(false),
            getReputation: jest.fn().mockResolvedValue({ score: 0, riskLevel: 'LOW' }),
          },
        },
        {
          provide: RateLimitingService,
          useValue: {
            isRequestAllowed: jest.fn().mockResolvedValue({ allowed: true, remaining: -1, resetTime: new Date() }),
          },
        },
        {
          provide: 'REDIS',
          useValue: {
            get: jest.fn(),
            setex: jest.fn(),
            del: jest.fn(),
          } as Partial<Redis>,
        },
      ],
    }).compile();

    controller = module.get<AdminController>(AdminController);
    adminService = module.get<AdminService>(AdminService);
    eventLogService = module.get<EventLogService>(EventLogService);
    prismaService = module.get<PrismaService>(PrismaService); // Get reference if needed for per-test mocks
  });

  describe('POST /users/bulk/roles', () => {
    it('should perform bulk role assignment successfully', async () => {
      const mockBulkResult = {
        totalUsers: 3,
        successfulUpdates: 3,
        failedUpdates: 0,
        results: [
          { userId: 'user-1', success: true },
          { userId: 'user-2', success: true },
          { userId: 'user-3', success: true },
        ],
      };

      jest.spyOn(adminService, 'bulkUpdateUserRoles').mockResolvedValue(mockBulkResult);

      const result = await controller.bulkUpdateUserRoles(
        mockRequest,
        ['user-1', 'user-2', 'user-3'],
        ['role-1', 'role-2'],
        'ASSIGN'
      );

      expect(adminService.bulkUpdateUserRoles).toHaveBeenCalledWith(
        ['user-1', 'user-2', 'user-3'],
        ['role-1', 'role-2'],
        'ASSIGN',
        'admin-user-id',
        undefined
      );
      expect(eventLogService.logEvent).toHaveBeenCalledWith('USER_PROFILE_UPDATE', {
        userId: 'admin-user-id',
        tenantId: 'tenant-id',
        metadata: {
          action: 'BULK_ROLE_UPDATE_COMPLETED',
          totalUsers: 3,
          successfulUpdates: 3,
          failedUpdates: 0,
          operation: 'ASSIGN',
          roleIds: ['role-1', 'role-2'],
          reason: undefined,
        },
        ipAddress: '127.0.0.1',
        userAgent: 'test-agent',
        severity: 'SECURITY',
      });
      expect(result).toEqual(mockBulkResult);
    });

    it('should perform bulk role removal successfully', async () => {
      const mockBulkResult = {
        totalUsers: 2,
        successfulUpdates: 2,
        failedUpdates: 0,
        results: [
          { userId: 'user-1', success: true },
          { userId: 'user-2', success: true },
        ],
      };

      jest.spyOn(adminService, 'bulkUpdateUserRoles').mockResolvedValue(mockBulkResult);

      const result = await controller.bulkUpdateUserRoles(
        mockRequest,
        ['user-1', 'user-2'],
        ['role-1'],
        'REMOVE'
      );

      expect(adminService.bulkUpdateUserRoles).toHaveBeenCalledWith(
        ['user-1', 'user-2'],
        ['role-1'],
        'REMOVE',
        'admin-user-id',
        undefined
      );
      expect(result).toEqual(mockBulkResult);
    });

    it('should perform bulk role replacement successfully', async () => {
      const mockBulkResult = {
        totalUsers: 1,
        successfulUpdates: 1,
        failedUpdates: 0,
        results: [
          { userId: 'user-1', success: true },
        ],
      };

      jest.spyOn(adminService, 'bulkUpdateUserRoles').mockResolvedValue(mockBulkResult);

      const result = await controller.bulkUpdateUserRoles(
        mockRequest,
        ['user-1'],
        ['new-role-1', 'new-role-2'],
        'REPLACE'
      );

      expect(adminService.bulkUpdateUserRoles).toHaveBeenCalledWith(
        ['user-1'],
        ['new-role-1', 'new-role-2'],
        'REPLACE',
        'admin-user-id',
        undefined
      );
      expect(result).toEqual(mockBulkResult);
    });

    it('should perform bulk operation with reason', async () => {
      const mockBulkResult = {
        totalUsers: 1,
        successfulUpdates: 1,
        failedUpdates: 0,
        results: [
          { userId: 'user-1', success: true },
        ],
      };

      jest.spyOn(adminService, 'bulkUpdateUserRoles').mockResolvedValue(mockBulkResult);

      const result = await controller.bulkUpdateUserRoles(
        mockRequest,
        ['user-1'],
        ['role-1'],
        'ASSIGN',
        'Bulk role assignment for new project'
      );

      expect(adminService.bulkUpdateUserRoles).toHaveBeenCalledWith(
        ['user-1'],
        ['role-1'],
        'ASSIGN',
        'admin-user-id',
        'Bulk role assignment for new project'
      );
      expect(result).toEqual(mockBulkResult);
    });

    it('should throw BadRequestException when userIds is empty array', async () => {
      await expect(controller.bulkUpdateUserRoles(
        mockRequest,
        [], // empty array
        ['role-1'],
        'ASSIGN'
      )).rejects.toThrow(BadRequestException);
      await expect(controller.bulkUpdateUserRoles(
        mockRequest,
        [], // empty array
        ['role-1'],
        'ASSIGN'
      )).rejects.toThrow('userIds must be a non-empty array');

      expect(eventLogService.logEvent).toHaveBeenCalledWith('ADMIN_VALIDATION_ERROR', {
        userId: 'admin-user-id',
        tenantId: 'tenant-id',
        metadata: {
          reason: 'invalid_user_ids_array',
          userIds: [],
        },
        ipAddress: '127.0.0.1',
        userAgent: 'test-agent',
        severity: 'SECURITY',
      });
    });

    it('should throw BadRequestException when userIds is not an array', async () => {
      await expect(controller.bulkUpdateUserRoles(
        mockRequest,
        null as any, // not an array
        ['role-1'],
        'ASSIGN'
      )).rejects.toThrow(BadRequestException);
      await expect(controller.bulkUpdateUserRoles(
        mockRequest,
        null as any, // not an array
        ['role-1'],
        'ASSIGN'
      )).rejects.toThrow('userIds must be a non-empty array');

      expect(eventLogService.logEvent).toHaveBeenCalledWith('ADMIN_VALIDATION_ERROR', {
        userId: 'admin-user-id',
        tenantId: 'tenant-id',
        metadata: {
          reason: 'invalid_user_ids_array',
          userIds: null,
        },
        ipAddress: '127.0.0.1',
        userAgent: 'test-agent',
        severity: 'SECURITY',
      });
    });

    it('should throw BadRequestException when roleIds is empty array', async () => {
      await expect(controller.bulkUpdateUserRoles(
        mockRequest,
        ['user-1'],
        [], // empty array
        'ASSIGN'
      )).rejects.toThrow(BadRequestException);
      await expect(controller.bulkUpdateUserRoles(
        mockRequest,
        ['user-1'],
        [], // empty array
        'ASSIGN'
      )).rejects.toThrow('roleIds must be a non-empty array');

      expect(eventLogService.logEvent).toHaveBeenCalledWith('ADMIN_VALIDATION_ERROR', {
        userId: 'admin-user-id',
        tenantId: 'tenant-id',
        metadata: {
          reason: 'invalid_role_ids_array',
          roleIds: [],
        },
        ipAddress: '127.0.0.1',
        userAgent: 'test-agent',
        severity: 'SECURITY',
      });
    });

    it('should throw BadRequestException when roleIds is not an array', async () => {
      await expect(controller.bulkUpdateUserRoles(
        mockRequest,
        ['user-1'],
        null as any, // not an array
        'ASSIGN'
      )).rejects.toThrow(BadRequestException);
      await expect(controller.bulkUpdateUserRoles(
        mockRequest,
        ['user-1'],
        null as any, // not an array
        'ASSIGN'
      )).rejects.toThrow('roleIds must be a non-empty array');

      expect(eventLogService.logEvent).toHaveBeenCalledWith('ADMIN_VALIDATION_ERROR', {
        userId: 'admin-user-id',
        tenantId: 'tenant-id',
        metadata: {
          reason: 'invalid_role_ids_array',
          roleIds: null,
        },
        ipAddress: '127.0.0.1',
        userAgent: 'test-agent',
        severity: 'SECURITY',
      });
    });

    it('should throw BadRequestException when operation is invalid', async () => {
      await expect(controller.bulkUpdateUserRoles(
        mockRequest,
        ['user-1'],
        ['role-1'],
        'INVALID_OPERATION' as any
      )).rejects.toThrow(BadRequestException);
      await expect(controller.bulkUpdateUserRoles(
        mockRequest,
        ['user-1'],
        ['role-1'],
        'INVALID_OPERATION' as any
      )).rejects.toThrow('Operation must be ASSIGN, REMOVE, or REPLACE');

      expect(eventLogService.logEvent).toHaveBeenCalledWith('ADMIN_VALIDATION_ERROR', {
        userId: 'admin-user-id',
        tenantId: 'tenant-id',
        metadata: {
          reason: 'invalid_operation_type',
          operation: 'INVALID_OPERATION',
        },
        ipAddress: '127.0.0.1',
        userAgent: 'test-agent',
        severity: 'SECURITY',
      });
    });

    it('should handle mixed success and failure results', async () => {
      const mockBulkResult = {
        totalUsers: 3,
        successfulUpdates: 2,
        failedUpdates: 1,
        results: [
          { userId: 'user-1', success: true },
          { userId: 'user-2', success: false, error: 'User not found' },
          { userId: 'user-3', success: true },
        ],
      };

      jest.spyOn(adminService, 'bulkUpdateUserRoles').mockResolvedValue(mockBulkResult);

      const result = await controller.bulkUpdateUserRoles(
        mockRequest,
        ['user-1', 'user-2', 'user-3'],
        ['role-1'],
        'ASSIGN'
      );

      expect(result).toEqual(mockBulkResult);
      expect(adminService.bulkUpdateUserRoles).toHaveBeenCalledWith(
        ['user-1', 'user-2', 'user-3'],
        ['role-1'],
        'ASSIGN',
        'admin-user-id',
        undefined
      );
    });

    it('should handle large bulk operations', async () => {
      const userIds = Array.from({ length: 100 }, (_, i) => `user-${i + 1}`);
      const mockBulkResult = {
        totalUsers: 100,
        successfulUpdates: 100,
        failedUpdates: 0,
        results: userIds.map(id => ({ userId: id, success: true })),
      };

      jest.spyOn(adminService, 'bulkUpdateUserRoles').mockResolvedValue(mockBulkResult);

      const result = await controller.bulkUpdateUserRoles(
        mockRequest,
        userIds,
        ['role-1'],
        'ASSIGN'
      );

      expect(result).toEqual(mockBulkResult);
      expect(adminService.bulkUpdateUserRoles).toHaveBeenCalledWith(
        userIds,
        ['role-1'],
        'ASSIGN',
        'admin-user-id',
        undefined
      );
    });

    it('should throw BadRequestException when bulk operation exceeds limit', async () => {
      const userIds = Array.from({ length: 101 }, (_, i) => `user-${i + 1}`);
      
      const mockError = new BadRequestException('Bulk operations are limited to 100 users at a time');
      jest.spyOn(adminService, 'bulkUpdateUserRoles').mockRejectedValue(mockError);

      await expect(controller.bulkUpdateUserRoles(
        mockRequest,
        userIds,
        ['role-1'],
        'ASSIGN'
      )).rejects.toThrow(BadRequestException);
      await expect(controller.bulkUpdateUserRoles(
        mockRequest,
        userIds,
        ['role-1'],
        'ASSIGN'
      )).rejects.toThrow('Bulk operations are limited to 100 users at a time');
    });

    it('should handle operation with multiple roles', async () => {
      const mockBulkResult = {
        totalUsers: 2,
        successfulUpdates: 2,
        failedUpdates: 0,
        results: [
          { userId: 'user-1', success: true },
          { userId: 'user-2', success: true },
        ],
      };

      jest.spyOn(adminService, 'bulkUpdateUserRoles').mockResolvedValue(mockBulkResult);

      const result = await controller.bulkUpdateUserRoles(
        mockRequest,
        ['user-1', 'user-2'],
        ['role-1', 'role-2', 'role-3', 'role-4'],
        'ASSIGN'
      );

      expect(adminService.bulkUpdateUserRoles).toHaveBeenCalledWith(
        ['user-1', 'user-2'],
        ['role-1', 'role-2', 'role-3', 'role-4'],
        'ASSIGN',
        'admin-user-id',
        undefined
      );
      expect(result).toEqual(mockBulkResult);
    });

    it('should log bulk operation completion event', async () => {
      const mockBulkResult = {
        totalUsers: 5,
        successfulUpdates: 4,
        failedUpdates: 1,
        results: [
          { userId: 'user-1', success: true },
          { userId: 'user-2', success: true },
          { userId: 'user-3', success: false, error: 'User not found' },
          { userId: 'user-4', success: true },
          { userId: 'user-5', success: true },
        ],
      };

      jest.spyOn(adminService, 'bulkUpdateUserRoles').mockResolvedValue(mockBulkResult);

      await controller.bulkUpdateUserRoles(
        mockRequest,
        ['user-1', 'user-2', 'user-3', 'user-4', 'user-5'],
        ['role-1', 'role-2'],
        'REMOVE',
        'Bulk role removal'
      );

      expect(eventLogService.logEvent).toHaveBeenCalledWith('USER_PROFILE_UPDATE', expect.objectContaining({
        userId: 'admin-user-id',
        tenantId: 'tenant-id',
        metadata: {
          action: 'BULK_ROLE_UPDATE_COMPLETED',
          totalUsers: 5,
          successfulUpdates: 4,
          failedUpdates: 1,
          operation: 'REMOVE',
          roleIds: ['role-1', 'role-2'],
          reason: 'Bulk role removal',
        },
        severity: 'SECURITY',
      }));
    });

    it('should handle complex role assignment with special characters', async () => {
      const mockBulkResult = {
        totalUsers: 1,
        successfulUpdates: 1,
        failedUpdates: 0,
        results: [
          { userId: 'user-1', success: true },
        ],
      };

      jest.spyOn(adminService, 'bulkUpdateUserRoles').mockResolvedValue(mockBulkResult);

      const result = await controller.bulkUpdateUserRoles(
        mockRequest,
        ['user-1'],
        ['role-with-special-chars-123', 'role_with_underscores', 'role.with.dots'],
        'ASSIGN'
      );

      expect(adminService.bulkUpdateUserRoles).toHaveBeenCalledWith(
        ['user-1'],
        ['role-with-special-chars-123', 'role_with_underscores', 'role.with.dots'],
        'ASSIGN',
        'admin-user-id',
        undefined
      );
      expect(result).toEqual(mockBulkResult);
    });

    it('should handle UUID role IDs', async () => {
      const mockBulkResult = {
        totalUsers: 1,
        successfulUpdates: 1,
        failedUpdates: 0,
        results: [
          { userId: 'user-1', success: true },
        ],
      };

      jest.spyOn(adminService, 'bulkUpdateUserRoles').mockResolvedValue(mockBulkResult);

      const result = await controller.bulkUpdateUserRoles(
        mockRequest,
        ['user-1'],
        ['a1b2c3d4-e5f6-7890-1234-567890abcdef', 'f0e9d8c7-b6a5-4321-fedc-ba9876543210'],
        'ASSIGN'
      );

      expect(adminService.bulkUpdateUserRoles).toHaveBeenCalledWith(
        ['user-1'],
        ['a1b2c3d4-e5f6-7890-1234-567890abcdef', 'f0e9d8c7-b6a5-4321-fedc-ba9876543210'],
        'ASSIGN',
        'admin-user-id',
        undefined
      );
      expect(result).toEqual(mockBulkResult);
    });
  });

  describe('Bulk Operations Edge Cases', () => {
    it('should handle bulk operations with duplicate user IDs', async () => {
      const mockBulkResult = {
        totalUsers: 3,
        successfulUpdates: 3,
        failedUpdates: 0,
        results: [
          { userId: 'user-1', success: true },
          { userId: 'user-1', success: true }, // duplicate
          { userId: 'user-2', success: true },
        ],
      };

      jest.spyOn(adminService, 'bulkUpdateUserRoles').mockResolvedValue(mockBulkResult);

      const result = await controller.bulkUpdateUserRoles(
        mockRequest,
        ['user-1', 'user-1', 'user-2'], // duplicate user IDs
        ['role-1'],
        'ASSIGN'
      );

      expect(result).toEqual(mockBulkResult);
    });

    it('should handle bulk operations with duplicate role IDs', async () => {
      const mockBulkResult = {
        totalUsers: 1,
        successfulUpdates: 1,
        failedUpdates: 0,
        results: [
          { userId: 'user-1', success: true },
        ],
      };

      jest.spyOn(adminService, 'bulkUpdateUserRoles').mockResolvedValue(mockBulkResult);

      const result = await controller.bulkUpdateUserRoles(
        mockRequest,
        ['user-1'],
        ['role-1', 'role-1', 'role-2'], // duplicate role IDs
        'ASSIGN'
      );

      expect(result).toEqual(mockBulkResult);
    });

    it('should handle bulk operations with mixed success scenarios', async () => {
      const mockBulkResult = {
        totalUsers: 5,
        successfulUpdates: 3,
        failedUpdates: 2,
        results: [
          { userId: 'user-1', success: true },
          { userId: 'user-2', success: false, error: 'User not found' },
          { userId: 'user-3', success: true },
          { userId: 'user-4', success: false, error: 'Role not found' },
          { userId: 'user-5', success: true },
        ],
      };

      jest.spyOn(adminService, 'bulkUpdateUserRoles').mockResolvedValue(mockBulkResult);

      const result = await controller.bulkUpdateUserRoles(
        mockRequest,
        ['user-1', 'user-2', 'user-3', 'user-4', 'user-5'],
        ['role-1', 'role-2'],
        'ASSIGN'
      );

      expect(result).toEqual(mockBulkResult);
    });
  });
});