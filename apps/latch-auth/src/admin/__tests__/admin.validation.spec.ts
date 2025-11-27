//admin.validation.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException, NotFoundException, ForbiddenException } from '@nestjs/common';
import { Request } from 'express';
import { AdminController } from '../admin.controller';
import { AdminService } from '../admin.service';
import { EventLogService } from '@/events/event.service';
import { PrismaService } from '@/prisma/prisma.service'; 
import { Redis } from 'ioredis'; 
import { RateLimitingService } from '@/rate-limiting/rate-limiting.service';
import { IPReputationService } from '@/ip-reputation/ip-reputation.service';
// Mock request object
const mockRequest = {
  user: { sub: 'user-id', tenantId: 'tenant-id' },
  ip: '127.0.0.1',
  headers: { 'user-agent': 'test-agent' },
} as Request;

describe('AdminController - Validation', () => {
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
            findAllUsers: jest.fn(),
            updateUserRole: jest.fn(),
            getAuditEvents: jest.fn(),
            getRoleAnalytics: jest.fn(),
            getTenantUserStats: jest.fn(),
            bulkUpdateUserRoles: jest.fn(),
            getUserRoleDetails: jest.fn(),
            // Add other methods if the validation tests indirectly call them or if AdminService instantiation requires them
          },
        },
        {
          provide: EventLogService,
          useValue: {
            logEvent: jest.fn(), // Mock logEvent
            // Add other methods if the validation methods use them, e.g., queryEvents
            queryEvents: jest.fn(),
          },
        },
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
          },
        },
        {
          provide: IPReputationService, // ADD THIS - needed by AdminController
          useValue: {
            isIPBlocked: jest.fn().mockResolvedValue(false),
            getReputation: jest.fn().mockResolvedValue({ score: 0, riskLevel: 'LOW' }),
            // Add other methods that AdminController might call
          },
        },
        // ADD PrismaService mock - This resolves the dependency for RolesGuard and other guards/controllers
        {
          provide: PrismaService,
          useValue: {
            // Mock the methods that RolesGuard, TenantGuard, CsrfGuard, or JwtAuthGuard might need
            // based on the specific tests. For validation tests, guards might need:
            // - RolesGuard: prisma.userRole.findMany to check roles
            // - TenantGuard: prisma.tenant.findUnique for tenant isolation
            // - JwtAuthGuard (if it fetches user details beyond the token): prisma.user.findUnique
            // - CsrfGuard: prisma.session.findUnique to validate session/csrf token
            userRole: {
              findMany: jest.fn(),
              // Add other methods if guards use them
            },
            tenant: {
              findUnique: jest.fn(),
              // Add other methods if guards use them
            },
            user: {
              findUnique: jest.fn(),
              // Add other methods if guards use them
            },
            session: { // Needed by CsrfGuard or potentially JwtAuthGuard
              findUnique: jest.fn(),
              // Add other methods if guards use them
            },
            // Add other models/methods potentially used by AdminService methods if they query directly via Prisma
            // e.g., prisma.user.findMany for findAllUsers, prisma.event.findMany/count for getAuditEvents
            // These might be needed later if the tests for those methods run successfully past the guards
            // user: {
            //   findMany: jest.fn(),
            //   // ... other methods
            // },
            // event: {
            //   findMany: jest.fn(),
            //   count: jest.fn(),
            //   // ... other methods
            // },
            // Add $transaction mock if any part of the flow (guards, service) uses transactions
            $transaction: jest.fn().mockImplementation(async (callback) => {
              // Define a basic transaction mock structure if needed by AdminService methods
              // This is a simplified example, adjust based on actual transaction usage
              const tx = {
                userRole: {
                  findMany: jest.fn(),
                  // ... other methods
                },
                tenant: {
                  findUnique: jest.fn(),
                  // ... other methods
                },
                // ... other models as needed for the transaction
              };
              return await callback(tx);
            }),
          },
        },
        // ADD REDIS mock if AdminService requires it
        {
          provide: 'REDIS', // The token used by AdminService to inject Redis
          useValue: {
            get: jest.fn(),
            setex: jest.fn(),
            del: jest.fn(),
            // Add other methods used by AdminService if needed by these endpoints
          } as Partial<Redis>,
        },
      ],
    })
    // Ensure AdminService is correctly instantiated with its dependencies
    .compile();

    controller = module.get<AdminController>(AdminController);
    adminService = module.get<AdminService>(AdminService);
    eventLogService = module.get<EventLogService>(EventLogService);
    prismaService = module.get<PrismaService>(PrismaService); // Get reference if needed for per-test mocks
  });

  describe('GET /users - Validation', () => {
    it('should throw BadRequestException when limit is less than 1', async () => {
      await expect(controller.findAllUsers(mockRequest, 0, 0)).rejects.toThrow(BadRequestException);
      await expect(controller.findAllUsers(mockRequest, 0, 0)).rejects.toThrow('Limit must be between 1 and 100');

      expect(eventLogService.logEvent).toHaveBeenCalledWith('ADMIN_VALIDATION_ERROR', {
        userId: 'user-id',
        tenantId: 'tenant-id',
        metadata: {
          reason: 'invalid_pagination_params',
          limit: 0,
          offset: 0,
        },
        ipAddress: '127.0.0.1',
        userAgent: 'test-agent',
        severity: 'SECURITY',
      });
    });

    it('should throw BadRequestException when limit is greater than 100', async () => {
      await expect(controller.findAllUsers(mockRequest, 101, 0)).rejects.toThrow(BadRequestException);
      await expect(controller.findAllUsers(mockRequest, 101, 0)).rejects.toThrow('Limit must be between 1 and 100');

      expect(eventLogService.logEvent).toHaveBeenCalledWith('ADMIN_VALIDATION_ERROR', {
        userId: 'user-id',
        tenantId: 'tenant-id',
        metadata: {
          reason: 'invalid_pagination_params',
          limit: 101,
          offset: 0,
        },
        ipAddress: '127.0.0.1',
        userAgent: 'test-agent',
        severity: 'SECURITY',
      });
    });

    it('should throw BadRequestException when offset is negative', async () => {
      await expect(controller.findAllUsers(mockRequest, 50, -1)).rejects.toThrow(BadRequestException);
      await expect(controller.findAllUsers(mockRequest, 50, -1)).rejects.toThrow('Offset must be >= 0');

      expect(eventLogService.logEvent).toHaveBeenCalledWith('ADMIN_VALIDATION_ERROR', {
        userId: 'user-id',
        tenantId: 'tenant-id',
        metadata: {
          reason: 'invalid_offset_param',
          offset: -1,
        },
        ipAddress: '127.0.0.1',
        userAgent: 'test-agent',
        severity: 'SECURITY',
      });
    });

    it('should handle valid limit values correctly', async () => {
      const mockUsersResponse = {
         data:[],
        meta: {
          total: 0,
          limit: 50,
          offset: 0,
          hasNext: false,
        },
      };

      jest.spyOn(adminService, 'findAllUsers').mockResolvedValue(mockUsersResponse);

      // Test with minimum valid limit
      const result1 = await controller.findAllUsers(mockRequest, 1, 0);
      expect(adminService.findAllUsers).toHaveBeenCalledWith(1, 0, undefined, false, undefined, undefined);
      expect(result1).toEqual(mockUsersResponse);

      // Reset mock
      jest.clearAllMocks();
      jest.spyOn(adminService, 'findAllUsers').mockResolvedValue(mockUsersResponse);

      // Test with maximum valid limit
      const result2 = await controller.findAllUsers(mockRequest, 100, 0);
      expect(adminService.findAllUsers).toHaveBeenCalledWith(100, 0, undefined, false, undefined, undefined);
      expect(result2).toEqual(mockUsersResponse);
    });

    it('should handle valid offset values correctly', async () => {
      const mockUsersResponse = {
         data: [],
        meta: {
          total: 0,
          limit: 50,
          offset: 0,
          hasNext: false,
        },
      };

      jest.spyOn(adminService, 'findAllUsers').mockResolvedValue(mockUsersResponse);

      // Test with zero offset
      const result = await controller.findAllUsers(mockRequest, 50, 0);
      expect(adminService.findAllUsers).toHaveBeenCalledWith(50, 0, undefined, false, undefined, undefined);
      expect(result).toEqual(mockUsersResponse);
    });
  });

  describe('GET /audit/events - Validation', () => {
    it('should throw BadRequestException when limit is less than 1', async () => {
      await expect(controller.getAuditEvents(mockRequest, 0, 0)).rejects.toThrow(BadRequestException);
      await expect(controller.getAuditEvents(mockRequest, 0, 0)).rejects.toThrow('Limit must be between 1 and 100');

      expect(eventLogService.logEvent).toHaveBeenCalledWith('ADMIN_VALIDATION_ERROR', {
        userId: 'user-id',
        tenantId: 'tenant-id',
        metadata: {
          reason: 'invalid_pagination_params',
          limit: 0,
          offset: 0,
        },
        ipAddress: '127.0.0.1',
        userAgent: 'test-agent',
        severity: 'SECURITY',
      });
    });

    it('should throw BadRequestException when limit is greater than 100', async () => {
      await expect(controller.getAuditEvents(mockRequest, 101, 0)).rejects.toThrow(BadRequestException);
      await expect(controller.getAuditEvents(mockRequest, 101, 0)).rejects.toThrow('Limit must be between 1 and 100');

      expect(eventLogService.logEvent).toHaveBeenCalledWith('ADMIN_VALIDATION_ERROR', {
        userId: 'user-id',
        tenantId: 'tenant-id',
        metadata: {
          reason: 'invalid_pagination_params',
          limit: 101,
          offset: 0,
        },
        ipAddress: '127.0.0.1',
        userAgent: 'test-agent',
        severity: 'SECURITY',
      });
    });

    it('should throw BadRequestException when offset is negative', async () => {
      await expect(controller.getAuditEvents(mockRequest, 50, -1)).rejects.toThrow(BadRequestException);
      await expect(controller.getAuditEvents(mockRequest, 50, -1)).rejects.toThrow('Offset must be >= 0');

      expect(eventLogService.logEvent).toHaveBeenCalledWith('ADMIN_VALIDATION_ERROR', {
        userId: 'user-id',
        tenantId: 'tenant-id',
        metadata: {
          reason: 'invalid_offset_param',
          offset: -1,
        },
        ipAddress: '127.0.0.1',
        userAgent: 'test-agent',
        severity: 'SECURITY',
      });
    });

    it('should throw BadRequestException when startDate format is invalid', async () => {
      await expect(controller.getAuditEvents(
        mockRequest,
        50,
        0,
        undefined,
        undefined,
        'invalid-date-format',
        undefined
      )).rejects.toThrow(BadRequestException);
      await expect(controller.getAuditEvents(
        mockRequest,
        50,
        0,
        undefined,
        undefined,
        'invalid-date-format',
        undefined
      )).rejects.toThrow('Invalid startDate format. Must be ISO 8601.');

      expect(eventLogService.logEvent).toHaveBeenCalledWith('ADMIN_VALIDATION_ERROR', {
        userId: 'user-id',
        tenantId: 'tenant-id',
        metadata: {
          reason: 'invalid_start_date_format',
          startDate: 'invalid-date-format',
        },
        ipAddress: '127.0.0.1',
        userAgent: 'test-agent',
        severity: 'SECURITY',
      });
    });

    it('should throw BadRequestException when endDate format is invalid', async () => {
      await expect(controller.getAuditEvents(
        mockRequest,
        50,
        0,
        undefined,
        undefined,
        undefined,
        'invalid-date-format'
      )).rejects.toThrow(BadRequestException);
      await expect(controller.getAuditEvents(
        mockRequest,
        50,
        0,
        undefined,
        undefined,
        undefined,
        'invalid-date-format'
      )).rejects.toThrow('Invalid endDate format. Must be ISO 8601.');

      expect(eventLogService.logEvent).toHaveBeenCalledWith('ADMIN_VALIDATION_ERROR', {
        userId: 'user-id',
        tenantId: 'tenant-id',
        metadata: {
          reason: 'invalid_end_date_format',
          endDate: 'invalid-date-format',
        },
        ipAddress: '127.0.0.1',
        userAgent: 'test-agent',
        severity: 'SECURITY',
      });
    });

    it('should handle valid date formats correctly', async () => {
      const mockAuditEvents = {
         data: [],
        meta: {
          total: 0,
          limit: 50,
          offset: 0,
          hasNext: false,
        }
      };

      jest.spyOn(adminService, 'getAuditEvents').mockResolvedValue(mockAuditEvents);

      const result = await controller.getAuditEvents(
        mockRequest,
        50,
        0,
        undefined,
        undefined,
        '2023-01-01T00:00:00.000Z',
        '2023-12-31T23:59:59.999Z'
      );

      expect(adminService.getAuditEvents).toHaveBeenCalledWith(
        50,
        0,
        undefined,
        undefined,
        new Date('2023-01-01T00:00:00.000Z'),
        new Date('2023-12-31T23:59:59.999Z'),
        undefined,
        undefined
      );
      expect(result).toEqual(mockAuditEvents);
    });

    it('should handle various valid date formats', async () => {
      const mockAuditEvents = {
        data: [],
        meta: {
          total: 0,
          limit: 50,
          offset: 0,
          hasNext: false,
        }
      };

      jest.spyOn(adminService, 'getAuditEvents').mockResolvedValue(mockAuditEvents);

      // Test with different valid date formats
      const formats = [
        '2023-06-15T10:30:00Z',
        '2023-06-15T10:30:00.123Z',
        '2023-06-15T10:30:00.123456Z',
        '2023-06-15T10:30:00+00:00',
        '2023-06-15T10:30:00.123+00:00',
      ];

      for (const format of formats) {
        await controller.getAuditEvents(
          mockRequest,
          50,
          0,
          undefined,
          undefined,
          format,
          undefined
        );
        
        expect(adminService.getAuditEvents).toHaveBeenCalledWith(
          50,
          0,
          undefined,
          undefined,
          new Date(format),
          undefined,
          undefined,
          undefined
        );
      }
    });

    it('should handle valid limit and offset combinations', async () => {
      const mockAuditEvents = {
        data: [],
        meta: {
          total: 0,
          limit: 25,
          offset: 50,
          hasNext: false,
        }
      };

      jest.spyOn(adminService, 'getAuditEvents').mockResolvedValue(mockAuditEvents);

      const result = await controller.getAuditEvents(
        mockRequest,
        25,
        50
      );

      expect(adminService.getAuditEvents).toHaveBeenCalledWith(
        25,
        50,
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        undefined
      );
      expect(result).toEqual(mockAuditEvents);
    });
  });

  describe('POST /users/bulk/roles - Validation', () => {
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
        userId: 'user-id',
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
        userId: 'user-id',
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
        userId: 'user-id',
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
        userId: 'user-id',
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
        userId: 'user-id',
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

    it('should handle valid operation values correctly', async () => {
      const mockBulkResult = {
        totalUsers: 1,
        successfulUpdates: 1,
        failedUpdates: 0,
        results: [
          { userId: 'user-1', success: true },
        ],
      };

      jest.spyOn(adminService, 'bulkUpdateUserRoles').mockResolvedValue(mockBulkResult);

      // Test ASSIGN operation
      await controller.bulkUpdateUserRoles(
        mockRequest,
        ['user-1'],
        ['role-1'],
        'ASSIGN'
      );
      expect(adminService.bulkUpdateUserRoles).toHaveBeenCalledWith(
        ['user-1'],
        ['role-1'],
        'ASSIGN',
        'user-id',
        undefined
      );

      // Reset mock
      jest.clearAllMocks();
      jest.spyOn(adminService, 'bulkUpdateUserRoles').mockResolvedValue(mockBulkResult);

      // Test REMOVE operation
      await controller.bulkUpdateUserRoles(
        mockRequest,
        ['user-1'],
        ['role-1'],
        'REMOVE'
      );
      expect(adminService.bulkUpdateUserRoles).toHaveBeenCalledWith(
        ['user-1'],
        ['role-1'],
        'REMOVE',
        'user-id',
        undefined
      );

      // Reset mock
      jest.clearAllMocks();
      jest.spyOn(adminService, 'bulkUpdateUserRoles').mockResolvedValue(mockBulkResult);

      // Test REPLACE operation
      await controller.bulkUpdateUserRoles(
        mockRequest,
        ['user-1'],
        ['role-1'],
        'REPLACE'
      );
      expect(adminService.bulkUpdateUserRoles).toHaveBeenCalledWith(
        ['user-1'],
        ['role-1'],
        'REPLACE',
        'user-id',
        undefined
      );
    });

    it('should handle valid user and role ID arrays', async () => {
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
        'user-id',
        undefined
      );
      expect(result).toEqual(mockBulkResult);
    });
  });

  describe('Validation Edge Cases', () => {
    it('should handle edge case values for pagination', async () => {
      const mockUsersResponse = {
        data: [],
        meta: {
          total: 0,
          limit: 1,
          offset: 0,
          hasNext: false,
        },
      };

      jest.spyOn(adminService, 'findAllUsers').mockResolvedValue(mockUsersResponse);

      // Test with minimum limit
      const result = await controller.findAllUsers(mockRequest, 1, 0);
      expect(adminService.findAllUsers).toHaveBeenCalledWith(1, 0, undefined, false, undefined, undefined);
      expect(result).toEqual(mockUsersResponse);
    });

    it('should handle large offset values', async () => {
      const mockUsersResponse = {
        data: [],
        meta: {
          total: 0,
          limit: 50,
          offset: 10000,
          hasNext: false,
        },
      };

      jest.spyOn(adminService, 'findAllUsers').mockResolvedValue(mockUsersResponse);

      const result = await controller.findAllUsers(mockRequest, 50, 10000);
      expect(adminService.findAllUsers).toHaveBeenCalledWith(50, 10000, undefined, false, undefined, undefined);
      expect(result).toEqual(mockUsersResponse);
    });

    it('should handle maximum pagination values', async () => {
      const mockAuditEvents = {
        data: [],
        meta: {
          total: 0,
          limit: 100,
          offset: 0,
          hasNext: false,
        }
      };

      jest.spyOn(adminService, 'getAuditEvents').mockResolvedValue(mockAuditEvents);

      const result = await controller.getAuditEvents(mockRequest, 100, 0);
      expect(adminService.getAuditEvents).toHaveBeenCalledWith(
        100,
        0,
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        undefined
      );
      expect(result).toEqual(mockAuditEvents);
    });

    it('should handle empty string parameters as undefined', async () => {
      const mockUsersResponse = {
        data: [],
        meta: {
          total: 0,
          limit: 50,
          offset: 0,
          hasNext: false,
        },
      };

      jest.spyOn(adminService, 'findAllUsers').mockResolvedValue(mockUsersResponse);

      const result = await controller.findAllUsers(
        mockRequest,
        50,
        0,
        '', // empty tenantId
        '', // empty includeRoleDetails
        '', // empty search
        ''  // empty status
      );

      expect(adminService.findAllUsers).toHaveBeenCalledWith(
        50,
        0,
        undefined, // should be undefined
        false,     // should be false
        undefined, // should be undefined
        undefined  // should be undefined
      );
      expect(result).toEqual(mockUsersResponse);
    });

    it('should handle null parameters', async () => {
      const mockUsersResponse = {
        data: [],
        meta: {
          total: 0,
          limit: 50,
          offset: 0,
          hasNext: false,
        },
      };

      jest.spyOn(adminService, 'findAllUsers').mockResolvedValue(mockUsersResponse);

      const result = await controller.findAllUsers(
        mockRequest,
        50,
        0,
        null as any, // null tenantId
        null as any, // null includeRoleDetails
        null as any, // null search
        null as any  // null status
      );

      expect(adminService.findAllUsers).toHaveBeenCalledWith(
        50,
        0,
        undefined, // should be undefined
        false,     // should be false
        undefined, // should be undefined
        undefined  // should be undefined
      );
      expect(result).toEqual(mockUsersResponse);
    });

    it('should handle very large number values', async () => {
      // This should still throw because the limit is too large
      await expect(controller.findAllUsers(mockRequest, 1000000, 0)).rejects.toThrow(BadRequestException);
      await expect(controller.findAllUsers(mockRequest, 1000000, 0)).rejects.toThrow('Limit must be between 1 and 100');
    });

    it('should handle date validation with timezone formats', async () => {
      const mockAuditEvents = {
         data: [],
        meta: {
          total: 0,
          limit: 50,
          offset: 0,
          hasNext: false,
        }
      };

      jest.spyOn(adminService, 'getAuditEvents').mockResolvedValue(mockAuditEvents);

      // Test with timezone offset formats
      const result = await controller.getAuditEvents(
        mockRequest,
        50,
        0,
        undefined,
        undefined,
        '2023-06-15T10:30:00+02:00',
        '2023-06-15T10:30:00-05:00'
      );

      expect(adminService.getAuditEvents).toHaveBeenCalledWith(
        50,
        0,
        undefined,
        undefined,
        new Date('2023-06-15T10:30:00+02:00'),
        new Date('2023-06-15T10:30:00-05:00'),
        undefined,
        undefined
      );
      expect(result).toEqual(mockAuditEvents);
    });

    it('should handle date validation with various edge cases', async () => {
      const mockAuditEvents = {
        data: [],
        meta: {
          total: 0,
          limit: 50,
          offset: 0,
          hasNext: false,
        }
      };

      jest.spyOn(adminService, 'getAuditEvents').mockResolvedValue(mockAuditEvents);

      // Test with minimal valid date format
      const result = await controller.getAuditEvents(
        mockRequest,
        50,
        0,
        undefined,
        undefined,
        '2023-01-01',
        undefined
      );

      // This should still work as the date parsing is flexible
      expect(adminService.getAuditEvents).toHaveBeenCalledWith(
        50,
        0,
        undefined,
        undefined,
        new Date('2023-01-01'),
        undefined,
        undefined,
        undefined
      );
      expect(result).toEqual(mockAuditEvents);
    });
  });
});