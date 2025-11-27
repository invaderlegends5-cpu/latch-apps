//admin.cache.spec.tsimport { Test, TestingModule } from '@nestjs/testing';
import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException, NotFoundException } from '@nestjs/common';
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

describe('AdminController - Cache', () => {
  let controller: AdminController;
  let adminService: AdminService;
  let eventLogService: EventLogService;
  let prismaService: PrismaService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({ // Now 'Test' should be defined
      controllers: [AdminController],
      providers: [
        {
          provide: AdminService,
          useValue: {
            findAllUsers: jest.fn(),
            getUserRoleDetails: jest.fn(),
            getRoleAnalytics: jest.fn(),
            getTenantUserStats: jest.fn(),
            updateUserRole: jest.fn(),
            getAuditEvents: jest.fn(),
            bulkUpdateUserRoles: jest.fn(),
          },
        },
        {
          provide: EventLogService,
          useValue: {
            logEvent: jest.fn(), // Mock logEvent
            // Add other methods if the cache tests use them, e.g., queryEvents
            queryEvents: jest.fn(),
          },
        },
        // ADD PrismaService mock - Crucial for guards like RolesGuard, TenantGuard
        {
          provide: PrismaService,
          useValue: {
            // Mock the methods that guards might use
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
              findMany: jest.fn(), // Might be needed by findAllUsers
              // Add other methods if needed by guards or service methods
            },
            session: { // Might be needed by JwtAuthGuard or CsrfGuard
              findUnique: jest.fn(),
              // Add other methods if needed by guards
            },
            // Add other models/methods as potentially required by AdminService methods used in these tests
            // e.g., if getUserRoleDetails uses Prisma directly
            // role: { findMany: jest.fn() },
            // Add $transaction mock if any part of the flow (guards, service) uses transactions
            $transaction: jest.fn().mockImplementation(async (callback) => {
              // Define a basic transaction mock structure if needed
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
                user: {
                  findUnique: jest.fn(),
                  findMany: jest.fn(),
                  // ... other methods
                },
                // ... other models as needed for the transaction
              };
              return await callback(tx);
            }),
          },
        },
        {
          provide: IPReputationService, // ADD THIS PROVIDER
          useValue: {
            isIPBlocked: jest.fn().mockResolvedValue(false),
            getReputation: jest.fn().mockResolvedValue({ score: 0, riskLevel: 'LOW' }),
            // Add other methods that AdminService might call
          },
        },
        {
          provide: RateLimitingService, // If still needed
          useValue: {
            isRequestAllowed: jest.fn().mockResolvedValue({ allowed: true, remaining: -1, resetTime: new Date() }),
          },
        },

        // ADD REDIS mock if AdminService requires it (e.g., for caching or session management if relevant to these endpoints)
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

  describe('GET /users - Cache Integration', () => {
    it('should retrieve users with default pagination and caching', async () => {
      const mockUsersResponse = {
        data: [
          {
            id: 'user-1',
            name: 'John Doe',
            email: 'john@example.com',
            phone: '+1234567890',
            tenantId: 'tenant-id',
            createdAt: new Date(),
            updatedAt: new Date(),
            isPhoneVerified: true,
            isEmailVerified: true,
            roleCount: 1,
            activeRoles: 1,
            tenant: {
              id: 'tenant-id',
              name: 'Test Tenant',
              slug: 'test-tenant',
            },
            roles: [
              {
                roleId: 'role-1',
                role: {
                  id: 'role-1',
                  name: 'admin',
                  description: 'Administrator role',
                  isSystem: false,
                  isActive: true,
                  validFrom: new Date(),
                  validUntil: new Date(Date.now() + 100 * 365 * 24 * 60 * 60 * 1000),
                },
              },
            ],
          }
        ],
        meta: {
          total: 1,
          limit: 50,
          offset: 0,
          hasNext: false,
        },
      };

      jest.spyOn(adminService, 'findAllUsers').mockResolvedValue(mockUsersResponse);

      const result = await controller.findAllUsers(mockRequest, 50, 0, undefined, undefined, undefined, undefined);

      expect(adminService.findAllUsers).toHaveBeenCalledWith(50, 0, undefined, false, undefined, undefined);
      expect(eventLogService.logEvent).toHaveBeenCalledWith('USER_LIST_ACCESSED', {
        userId: 'user-id',
        tenantId: 'tenant-id',
        metadata: {
          action: 'LIST_USERS',
          limit: 50,
          offset: 0,
          tenantId: undefined,
          includeRoleDetails: false,
          search: undefined,
          status: undefined,
          total: 1,
        },
        ipAddress: '127.0.0.1',
        userAgent: 'test-agent',
        severity: 'INFO',
      });
      expect(result).toEqual(mockUsersResponse);
    });

    it('should retrieve users with custom pagination and caching', async () => {
      const mockUsersResponse = {
         data:[],
        meta: {
          total: 0,
          limit: 25,
          offset: 10,
          hasNext: false,
        },
      };

      jest.spyOn(adminService, 'findAllUsers').mockResolvedValue(mockUsersResponse);

      const result = await controller.findAllUsers(
        mockRequest,
        25, // limit
        10, // offset
        'specific-tenant-id', // tenantId
        'true', // includeRoleDetails
        'john', // search
        'active' // status
      );

      expect(adminService.findAllUsers).toHaveBeenCalledWith(
        25, // limit
        10, // offset
        'specific-tenant-id', // tenantId
        true, // includeRoleDetails
        'john', // search
        'active' // status
      );
      expect(result).toEqual(mockUsersResponse);
    });

    it('should handle includeRoleDetails parameter correctly', async () => {
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
        undefined,
        'true' // includeRoleDetails = true
      );

      expect(adminService.findAllUsers).toHaveBeenCalledWith(
        50,
        0,
        undefined,
        true, // includeRoleDetails should be true
        undefined,
        undefined
      );
      expect(result).toEqual(mockUsersResponse);
    });

    it('should handle includeRoleDetails parameter as false', async () => {
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
        undefined,
        'false' // includeRoleDetails = false
      );

      expect(adminService.findAllUsers).toHaveBeenCalledWith(
        50,
        0,
        undefined,
        false, // includeRoleDetails should be false
        undefined,
        undefined
      );
      expect(result).toEqual(mockUsersResponse);
    });

    it('should handle includeRoleDetails parameter as invalid value', async () => {
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
        undefined,
        'invalid' // includeRoleDetails = invalid, should default to false
      );

      expect(adminService.findAllUsers).toHaveBeenCalledWith(
        50,
        0,
        undefined,
        false, // includeRoleDetails should default to false
        undefined,
        undefined
      );
      expect(result).toEqual(mockUsersResponse);
    });

    it('should throw BadRequestException when limit is invalid', async () => {
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

    it('should handle tenant filtering in cache', async () => {
      const mockUsersResponse = {
        data: [
          {
            id: 'user-2',
            name: 'Jane Smith',
            email: 'jane@example.com',
            phone: '+0987654321',
            tenantId: 'other-tenant',
            createdAt: new Date(),
            updatedAt: new Date(),
            isPhoneVerified: false,
            isEmailVerified: true,
            roleCount: 2,
            activeRoles: 2,
            tenant: {
              id: 'other-tenant',
              name: 'Other Tenant',
              slug: 'other-tenant',
            },
            roles: [
              {
                roleId: 'role-2',
                role: {
                  id: 'role-2',
                  name: 'user',
                  description: 'User role',
                  isSystem: false,
                  isActive: true,
                  validFrom: new Date(),
                  validUntil: new Date(Date.now() + 100 * 365 * 24 * 60 * 60 * 1000),
                },
              },
              {
                roleId: 'role-3',
                role: {
                  id: 'role-3',
                  name: 'editor',
                  description: 'Editor role',
                  isSystem: false,
                  isActive: true,
                  validFrom: new Date(),
                  validUntil: new Date(Date.now() + 100 * 365 * 24 * 60 * 60 * 1000),
                },
              },
            ],
          }
        ],
        meta: {
          total: 1,
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
        'other-tenant' // tenantId
      );

      expect(adminService.findAllUsers).toHaveBeenCalledWith(
        50,
        0,
        'other-tenant', // tenantId
        false, // includeRoleDetails
        undefined,
        undefined
      );
      expect(result).toEqual(mockUsersResponse);
    });

    it('should handle search parameter with caching', async () => {
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
        undefined,
        undefined,
        'search-term' // search
      );

      expect(adminService.findAllUsers).toHaveBeenCalledWith(
        50,
        0,
        undefined,
        false,
        'search-term', // search
        undefined
      );
      expect(result).toEqual(mockUsersResponse);
    });

    it('should handle status parameter with caching', async () => {
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
        undefined,
        undefined,
        undefined,
        'inactive' // status
      );

      expect(adminService.findAllUsers).toHaveBeenCalledWith(
        50,
        0,
        undefined,
        false,
        undefined,
        'inactive' // status
      );
      expect(result).toEqual(mockUsersResponse);
    });

    it('should handle all parameters with caching', async () => {
      const mockUsersResponse = {
        data: [
          {
            id: 'user-3',
            name: 'Bob Johnson',
            email: 'bob@example.com',
            phone: '+1122334455',
            tenantId: 'filtered-tenant',
            createdAt: new Date(),
            updatedAt: new Date(),
            isPhoneVerified: true,
            isEmailVerified: false,
            roleCount: 0,
            activeRoles: 0,
            tenant: {
              id: 'filtered-tenant',
              name: 'Filtered Tenant',
              slug: 'filtered-tenant',
            },
            roles: [],
          }
        ],
        meta: {
          total: 1,
          limit: 75,
          offset: 25,
          hasNext: false,
        },
      };

      jest.spyOn(adminService, 'findAllUsers').mockResolvedValue(mockUsersResponse);

      const result = await controller.findAllUsers(
        mockRequest,
        75, // limit
        25, // offset
        'filtered-tenant', // tenantId
        'true', // includeRoleDetails
        'bob', // search
        'active' // status
      );

      expect(adminService.findAllUsers).toHaveBeenCalledWith(
        75, // limit
        25, // offset
        'filtered-tenant', // tenantId
        true, // includeRoleDetails
        'bob', // search
        'active' // status
      );
      expect(result).toEqual(mockUsersResponse);
    });
  });

  describe('GET /users/:userId/roles - Cache Integration', () => {
    it('should retrieve user role details with caching', async () => {
      const mockUserId = 'user-uuid';
      const mockUserRoleDetails = {
        userId: mockUserId,
        name: 'John Doe',
        email: 'john@example.com',
        roles: [
          {
            roleId: 'role-1',
            roleName: 'admin',
            roleDescription: 'Administrator role',
            permissions: [
              {
                permissionId: 'perm-1',
                permissionName: 'read_users',
                resource: 'users',
                action: 'read',
                allowed: true,
              },
              {
                permissionId: 'perm-2',
                permissionName: 'write_users',
                resource: 'users',
                action: 'write',
                allowed: false,
              },
            ],
          },
        ],
      };

      jest.spyOn(adminService, 'getUserRoleDetails').mockResolvedValue(mockUserRoleDetails);

      const result = await controller.getUserRoleDetails(mockUserId, mockRequest);

      expect(adminService.getUserRoleDetails).toHaveBeenCalledWith(mockUserId);
      expect(eventLogService.logEvent).toHaveBeenCalledWith('USER_DATA_ACCESSED', {
        userId: 'user-id',
        tenantId: 'tenant-id',
        metadata: {
          action: 'GET_USER_ROLE_DETAILS',
          targetUserId: mockUserId,
        },
        ipAddress: '127.0.0.1',
        userAgent: 'test-agent',
        severity: 'INFO',
      });
      expect(result).toEqual(mockUserRoleDetails);
    });

    it('should throw NotFoundException when user does not exist', async () => {
      const mockUserId = 'non-existent-user';
      const mockError = new NotFoundException(`User with id "${mockUserId}" not found`);

      jest.spyOn(adminService, 'getUserRoleDetails').mockRejectedValue(mockError);

      await expect(controller.getUserRoleDetails(mockUserId, mockRequest)).rejects.toThrow(NotFoundException);
      await expect(controller.getUserRoleDetails(mockUserId, mockRequest)).rejects.toThrow(`User with id "${mockUserId}" not found`);
    });

    it('should handle user with multiple roles and permissions', async () => {
      const mockUserId = 'user-uuid';
      const mockUserRoleDetails = {
        userId: mockUserId,
        name: 'Jane Smith',
        email: 'jane@example.com',
        roles: [
          {
            roleId: 'role-1',
            roleName: 'admin',
            roleDescription: 'Administrator role',
            permissions: [
              { permissionId: 'perm-1', permissionName: 'read_users', resource: 'users', action: 'read', allowed: true },
              { permissionId: 'perm-2', permissionName: 'write_users', resource: 'users', action: 'write', allowed: true },
              { permissionId: 'perm-3', permissionName: 'delete_users', resource: 'users', action: 'delete', allowed: true },
            ],
          },
          {
            roleId: 'role-2',
            roleName: 'editor',
            roleDescription: 'Editor role',
            permissions: [
              { permissionId: 'perm-4', permissionName: 'read_content', resource: 'content', action: 'read', allowed: true },
              { permissionId: 'perm-5', permissionName: 'write_content', resource: 'content', action: 'write', allowed: true },
            ],
          },
          {
            roleId: 'role-3',
            roleName: 'viewer',
            roleDescription: 'Viewer role',
            permissions: [
              { permissionId: 'perm-6', permissionName: 'read_content', resource: 'content', action: 'read', allowed: true },
            ],
          },
        ],
      };

      jest.spyOn(adminService, 'getUserRoleDetails').mockResolvedValue(mockUserRoleDetails);

      const result = await controller.getUserRoleDetails(mockUserId, mockRequest);

      expect(result).toEqual(mockUserRoleDetails);
      expect(adminService.getUserRoleDetails).toHaveBeenCalledWith(mockUserId);
    });

    it('should handle user with no roles', async () => {
      const mockUserId = 'user-without-roles';
      const mockUserRoleDetails = {
        userId: mockUserId,
        name: 'No Role User',
        email: 'norole@example.com',
        roles: [],
      };

      jest.spyOn(adminService, 'getUserRoleDetails').mockResolvedValue(mockUserRoleDetails);

      const result = await controller.getUserRoleDetails(mockUserId, mockRequest);

      expect(result).toEqual(mockUserRoleDetails);
      expect(adminService.getUserRoleDetails).toHaveBeenCalledWith(mockUserId);
    });

    it('should handle user with roles but no permissions', async () => {
      const mockUserId = 'user-no-permissions';
      const mockUserRoleDetails = {
        userId: mockUserId,
        name: 'No Permission User',
        email: 'noperm@example.com',
        roles: [
          {
            roleId: 'role-1',
            roleName: 'basic-user',
            roleDescription: 'Basic user role',
            permissions: [],
          },
        ],
      };

      jest.spyOn(adminService, 'getUserRoleDetails').mockResolvedValue(mockUserRoleDetails);

      const result = await controller.getUserRoleDetails(mockUserId, mockRequest);

      expect(result).toEqual(mockUserRoleDetails);
      expect(adminService.getUserRoleDetails).toHaveBeenCalledWith(mockUserId);
    });

    it('should handle complex permissions with nested resources', async () => {
      const mockUserId = 'complex-user';
      const mockUserRoleDetails = {
        userId: mockUserId,
        name: 'Complex User',
        email: 'complex@example.com',
        roles: [
          {
            roleId: 'role-1',
            roleName: 'admin',
            roleDescription: 'Administrator role',
            permissions: [
              { permissionId: 'perm-1', permissionName: 'read_users', resource: 'users', action: 'read', allowed: true },
              { permissionId: 'perm-2', permissionName: 'write_users', resource: 'users', action: 'write', allowed: true },
              { permissionId: 'perm-3', permissionName: 'read_tenant_data', resource: 'tenant:data', action: 'read', allowed: true },
              { permissionId: 'perm-4', permissionName: 'manage_system', resource: 'system:admin', action: 'manage', allowed: true },
            ],
          },
        ],
      };

      jest.spyOn(adminService, 'getUserRoleDetails').mockResolvedValue(mockUserRoleDetails);

      const result = await controller.getUserRoleDetails(mockUserId, mockRequest);

      expect(result).toEqual(mockUserRoleDetails);
      expect(adminService.getUserRoleDetails).toHaveBeenCalledWith(mockUserId);
    });
  });

  describe('Cache Integration Edge Cases', () => {
    it('should handle users with special characters in search', async () => {
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
        undefined,
        undefined,
        'search-with-special-chars-123!@#' // search with special chars
      );

      expect(adminService.findAllUsers).toHaveBeenCalledWith(
        50,
        0,
        undefined,
        false,
        'search-with-special-chars-123!@#',
        undefined
      );
      expect(result).toEqual(mockUsersResponse);
    });

    it('should handle tenant ID with UUID format', async () => {
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
        'a1b2c3d4-e5f6-7890-1234-567890abcdef' // UUID format tenant ID
      );

      expect(adminService.findAllUsers).toHaveBeenCalledWith(
        50,
        0,
        'a1b2c3d4-e5f6-7890-1234-567890abcdef',
        false,
        undefined,
        undefined
      );
      expect(result).toEqual(mockUsersResponse);
    });

    it('should handle user ID with UUID format', async () => {
      const mockUserId = 'f0e9d8c7-b6a5-4321-fedc-ba9876543210';
      const mockUserRoleDetails = {
        userId: mockUserId,
        name: 'UUID User',
        email: 'uuid@example.com',
        roles: [],
      };

      jest.spyOn(adminService, 'getUserRoleDetails').mockResolvedValue(mockUserRoleDetails);

      const result = await controller.getUserRoleDetails(mockUserId, mockRequest);

      expect(result).toEqual(mockUserRoleDetails);
      expect(adminService.getUserRoleDetails).toHaveBeenCalledWith(mockUserId);
    });

    it('should handle pagination with maximum values', async () => {
      const mockUsersResponse = {
         data: [],
        meta: {
          total: 0,
          limit: 100,
          offset: 0,
          hasNext: false,
        },
      };

      jest.spyOn(adminService, 'findAllUsers').mockResolvedValue(mockUsersResponse);

      const result = await controller.findAllUsers(
        mockRequest,
        100, // maximum limit
        0
      );

      expect(adminService.findAllUsers).toHaveBeenCalledWith(100, 0, undefined, false, undefined, undefined);
      expect(result).toEqual(mockUsersResponse);
    });
  });
});