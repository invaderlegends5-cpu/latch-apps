//admin.security.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException, NotFoundException, ForbiddenException, UnauthorizedException } from '@nestjs/common';
import { Request } from 'express';
import { AdminController } from '../admin.controller';
import { AdminService } from '../admin.service';
import { EventLogService } from '@/events/event.service';
import { TenantGuard } from '@/auth/guards/tenant.guard';
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

describe('AdminController - Security', () => {
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
            updateUserRole: jest.fn(),
            findAllUsers: jest.fn(),
            getAuditEvents: jest.fn(),
            getRoleAnalytics: jest.fn(),
            getTenantUserStats: jest.fn(),
            bulkUpdateUserRoles: jest.fn(),
            getUserRoleDetails: jest.fn(),
            // Add other methods if the security tests indirectly call them or if AdminService instantiation requires them
          },
        },
        {
          provide: EventLogService,
          useValue: {
            logEvent: jest.fn(), // Mock logEvent
            // Add other methods if the security methods use them, e.g., queryEvents
            queryEvents: jest.fn(),
          },
        },
        // ADD PrismaService mock - This resolves the dependency for RolesGuard and other guards/controllers
        {
          provide: PrismaService,
          useValue: {
            // Mock the methods that RolesGuard, TenantGuard, CsrfGuard, or JwtAuthGuard might need
            // based on the specific tests. For security tests, guards might need:
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
            // e.g., prisma.user.findUnique to validate target user ID in updateUserRole, prisma.role.findMany to validate role IDs
            // These might be needed later if the tests for updateUserRole run successfully past the guards
            // role: {
            //   findMany: jest.fn(),
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

  describe('PATCH /users/roles - Security', () => {
    it('should update user role successfully with proper security logging', async () => {
      const mockUpdateUserRoleDto = {
        userId: 'target-user-id',
        tenantId: 'tenant-id',
        operation: 'ASSIGN',
        roles: [{ roleId: 'role-1' }],
        reason: 'Security update',
      };

      const mockUpdateResult = {
        id: 'target-user-id',
        name: 'Target User',
        email: 'target@example.com',
        tenantId: 'tenant-id',
        message: 'Roles assigned successfully',
      };

      jest.spyOn(adminService, 'updateUserRole').mockResolvedValue(mockUpdateResult);

      const result = await controller.updateUserRole(mockUpdateUserRoleDto, mockRequest);

      expect(adminService.updateUserRole).toHaveBeenCalledWith(mockUpdateUserRoleDto, 'user-id');
      expect(eventLogService.logEvent).toHaveBeenCalledWith('USER_PROFILE_UPDATE', {
        userId: 'user-id',
        tenantId: 'tenant-id',
        metadata: {
          action: 'UPDATE_USER_ROLE_ATTEMPT',
          targetUserId: 'target-user-id',
          tenantId: 'tenant-id',
          operation: 'ASSIGN',
          roleCount: 1,
        },
        ipAddress: '127.0.0.1',
        userAgent: 'test-agent',
        severity: 'SECURITY',
      });
      expect(eventLogService.logEvent).toHaveBeenCalledWith('USER_PROFILE_UPDATE', {
        userId: 'user-id',
        tenantId: 'tenant-id',
        metadata: {
          action: 'UPDATE_USER_ROLE_SUCCESS',
          targetUserId: 'target-user-id',
          tenantId: 'tenant-id',
          operation: 'ASSIGN',
          roleCount: 1,
        },
        ipAddress: '127.0.0.1',
        userAgent: 'test-agent',
        severity: 'SECURITY',
      });
      expect(result).toEqual(mockUpdateResult);
    });

    it('should handle ASSIGN operation with multiple roles', async () => {
      const mockUpdateUserRoleDto = {
        userId: 'target-user-id',
        tenantId: 'tenant-id',
        operation: 'ASSIGN',
        roles: [
          { roleId: 'role-1' },
          { roleId: 'role-2' },
          { roleId: 'role-3' },
        ],
        reason: 'Multi-role assignment',
      };

      const mockUpdateResult = {
        id: 'target-user-id',
        name: 'Target User',
        email: 'target@example.com',
        tenantId: 'tenant-id',
        message: 'Roles assigned successfully',
      };

      jest.spyOn(adminService, 'updateUserRole').mockResolvedValue(mockUpdateResult);

      const result = await controller.updateUserRole(mockUpdateUserRoleDto, mockRequest);

      expect(adminService.updateUserRole).toHaveBeenCalledWith(mockUpdateUserRoleDto, 'user-id');
      expect(result).toEqual(mockUpdateResult);
    });

    it('should handle REMOVE operation', async () => {
      const mockUpdateUserRoleDto = {
        userId: 'target-user-id',
        tenantId: 'tenant-id',
        operation: 'REMOVE',
        roles: [{ roleId: 'role-1' }],
        reason: 'Role removal',
      };

      const mockUpdateResult = {
        id: 'target-user-id',
        name: 'Target User',
        email: 'target@example.com',
        tenantId: 'tenant-id',
        message: 'Roles removed successfully',
      };

      jest.spyOn(adminService, 'updateUserRole').mockResolvedValue(mockUpdateResult);

      const result = await controller.updateUserRole(mockUpdateUserRoleDto, mockRequest);

      expect(adminService.updateUserRole).toHaveBeenCalledWith(mockUpdateUserRoleDto, 'user-id');
      expect(result).toEqual(mockUpdateResult);
    });

    it('should handle REPLACE operation', async () => {
      const mockUpdateUserRoleDto = {
        userId: 'target-user-id',
        tenantId: 'tenant-id',
        operation: 'REPLACE',
        roles: [
          { roleId: 'new-role-1' },
          { roleId: 'new-role-2' },
        ],
        reason: 'Role replacement',
      };

      const mockUpdateResult = {
        id: 'target-user-id',
        name: 'Target User',
        email: 'target@example.com',
        tenantId: 'tenant-id',
        message: 'Roles replaced successfully',
      };

      jest.spyOn(adminService, 'updateUserRole').mockResolvedValue(mockUpdateResult);

      const result = await controller.updateUserRole(mockUpdateUserRoleDto, mockRequest);

      expect(adminService.updateUserRole).toHaveBeenCalledWith(mockUpdateUserRoleDto, 'user-id');
      expect(result).toEqual(mockUpdateResult);
    });

    it('should handle TEMPORARY_ASSIGN operation', async () => {
      const mockUpdateUserRoleDto = {
        userId: 'target-user-id',
        tenantId: 'tenant-id',
        operation: 'TEMPORARY_ASSIGN',
        roles: [{ roleId: 'temp-role-1' }],
        temporaryDurationDays: 7,
        reason: 'Temporary role assignment',
      };

      const mockUpdateResult = {
        id: 'target-user-id',
        name: 'Target User',
        email: 'target@example.com',
        tenantId: 'tenant-id',
        message: 'Roles temporarily assigned successfully',
      };

      jest.spyOn(adminService, 'updateUserRole').mockResolvedValue(mockUpdateResult);

      const result = await controller.updateUserRole(mockUpdateUserRoleDto, mockRequest);

      expect(adminService.updateUserRole).toHaveBeenCalledWith(mockUpdateUserRoleDto, 'user-id');
      expect(result).toEqual(mockUpdateResult);
    });

    it('should handle INHERIT operation', async () => {
      const mockUpdateUserRoleDto = {
        userId: 'target-user-id',
        tenantId: 'tenant-id',
        operation: 'INHERIT',
        roles: [{ roleId: 'parent-role-1' }],
        reason: 'Role inheritance',
      };

      const mockUpdateResult = {
        id: 'target-user-id',
        name: 'Target User',
        email: 'target@example.com',
        tenantId: 'tenant-id',
        message: 'Roles inherited successfully',
      };

      jest.spyOn(adminService, 'updateUserRole').mockResolvedValue(mockUpdateResult);

      const result = await controller.updateUserRole(mockUpdateUserRoleDto, mockRequest);

      expect(adminService.updateUserRole).toHaveBeenCalledWith(mockUpdateUserRoleDto, 'user-id');
      expect(result).toEqual(mockUpdateResult);
    });

    it('should throw BadRequestException for unsupported operation', async () => {
      const mockUpdateUserRoleDto = {
        userId: 'target-user-id',
        tenantId: 'tenant-id',
        operation: 'INVALID_OPERATION' as any,
        roles: [{ roleId: 'role-1' }],
        reason: 'Invalid operation',
      };

      const mockError = new BadRequestException('Unsupported operation: INVALID_OPERATION');
      jest.spyOn(adminService, 'updateUserRole').mockRejectedValue(mockError);

      await expect(controller.updateUserRole(mockUpdateUserRoleDto, mockRequest)).rejects.toThrow(BadRequestException);
      await expect(controller.updateUserRole(mockUpdateUserRoleDto, mockRequest)).rejects.toThrow('Unsupported operation: INVALID_OPERATION');
    });

    it('should throw BadRequestException for TEMPORARY_ASSIGN without duration', async () => {
      const mockUpdateUserRoleDto = {
        userId: 'target-user-id',
        tenantId: 'tenant-id',
        operation: 'TEMPORARY_ASSIGN',
        roles: [{ roleId: 'temp-role-1' }],
        // missing temporaryDurationDays
        reason: 'Temporary assignment without duration',
      };

      const mockError = new BadRequestException('temporaryDurationDays is required for TEMPORARY_ASSIGN operation');
      jest.spyOn(adminService, 'updateUserRole').mockRejectedValue(mockError);

      await expect(controller.updateUserRole(mockUpdateUserRoleDto, mockRequest)).rejects.toThrow(BadRequestException);
      await expect(controller.updateUserRole(mockUpdateUserRoleDto, mockRequest)).rejects.toThrow('temporaryDurationDays is required for TEMPORARY_ASSIGN operation');
    });

    it('should throw NotFoundException when user does not exist', async () => {
      const mockUpdateUserRoleDto = {
        userId: 'non-existent-user',
        tenantId: 'tenant-id',
        operation: 'ASSIGN',
        roles: [{ roleId: 'role-1' }],
        reason: 'User not found',
      };

      const mockError = new NotFoundException(`User with id "non-existent-user" not found`);
      jest.spyOn(adminService, 'updateUserRole').mockRejectedValue(mockError);

      await expect(controller.updateUserRole(mockUpdateUserRoleDto, mockRequest)).rejects.toThrow(NotFoundException);
      await expect(controller.updateUserRole(mockUpdateUserRoleDto, mockRequest)).rejects.toThrow('User with id "non-existent-user" not found');
    });

    it('should throw ForbiddenException when user does not belong to tenant', async () => {
      const mockUpdateUserRoleDto = {
        userId: 'user-from-different-tenant',
        tenantId: 'wrong-tenant-id',
        operation: 'ASSIGN',
        roles: [{ roleId: 'role-1' }],
        reason: 'Tenant mismatch',
      };

      const mockError = new ForbiddenException('User does not belong to the specified tenant');
      jest.spyOn(adminService, 'updateUserRole').mockRejectedValue(mockError);

      await expect(controller.updateUserRole(mockUpdateUserRoleDto, mockRequest)).rejects.toThrow(ForbiddenException);
      await expect(controller.updateUserRole(mockUpdateUserRoleDto, mockRequest)).rejects.toThrow('User does not belong to the specified tenant');
    });

    it('should throw NotFoundException when roles do not exist in tenant', async () => {
      const mockUpdateUserRoleDto = {
        userId: 'valid-user-id',
        tenantId: 'tenant-id',
        operation: 'ASSIGN',
        roles: [{ roleId: 'non-existent-role' }],
        reason: 'Role not found',
      };

      const mockError = new NotFoundException('Roles not found in tenant: non-existent-role');
      jest.spyOn(adminService, 'updateUserRole').mockRejectedValue(mockError);

      await expect(controller.updateUserRole(mockUpdateUserRoleDto, mockRequest)).rejects.toThrow(NotFoundException);
      await expect(controller.updateUserRole(mockUpdateUserRoleDto, mockRequest)).rejects.toThrow('Roles not found in tenant: non-existent-role');
    });

    it('should handle security logging for failed role updates', async () => {
      const mockUpdateUserRoleDto = {
        userId: 'target-user-id',
        tenantId: 'tenant-id',
        operation: 'ASSIGN',
        roles: [{ roleId: 'role-1' }],
        reason: 'Failed update test',
      };

      const mockError = new BadRequestException('Test error');
      jest.spyOn(adminService, 'updateUserRole').mockRejectedValue(mockError);

      await expect(controller.updateUserRole(mockUpdateUserRoleDto, mockRequest)).rejects.toThrow(BadRequestException);

      // Check that the attempt was logged
      expect(eventLogService.logEvent).toHaveBeenCalledWith('USER_PROFILE_UPDATE', {
        userId: 'user-id',
        tenantId: 'tenant-id',
        metadata: {
          action: 'UPDATE_USER_ROLE_ATTEMPT',
          targetUserId: 'target-user-id',
          tenantId: 'tenant-id',
          operation: 'ASSIGN',
          roleCount: 1,
        },
        ipAddress: '127.0.0.1',
        userAgent: 'test-agent',
        severity: 'SECURITY',
      });
    });

    it('should handle role update with multiple roles and complex metadata', async () => {
      const mockUpdateUserRoleDto = {
        userId: 'target-user-id',
        tenantId: 'tenant-id',
        operation: 'ASSIGN',
        roles: [
          { roleId: 'role-1', validFrom: '2023-01-01T00:00:00Z', validUntil: '2023-12-31T23:59:59Z' },
          { roleId: 'role-2', validFrom: '2023-06-01T00:00:00Z', validUntil: '2023-11-30T23:59:59Z' },
        ],
        reason: 'Complex role assignment',
        grantedBy: 'admin-user',
        notifyUser: true,
        bypassHierarchyCheck: false,
        temporaryDurationDays: 30,
        activationStrategy: 'immediate',
      };

      const mockUpdateResult = {
        id: 'target-user-id',
        name: 'Target User',
        email: 'target@example.com',
        tenantId: 'tenant-id',
        message: 'Roles assigned successfully',
      };

      jest.spyOn(adminService, 'updateUserRole').mockResolvedValue(mockUpdateResult);

      const result = await controller.updateUserRole(mockUpdateUserRoleDto, mockRequest);

      expect(adminService.updateUserRole).toHaveBeenCalledWith(mockUpdateUserRoleDto, 'user-id');
      expect(result).toEqual(mockUpdateResult);
    });

    it('should handle role update with special characters in reason', async () => {
      const mockUpdateUserRoleDto = {
        userId: 'target-user-id',
        tenantId: 'tenant-id',
        operation: 'ASSIGN',
        roles: [{ roleId: 'role-1' }],
        reason: 'Security update with special chars: !@#$%^&*()',
      };

      const mockUpdateResult = {
        id: 'target-user-id',
        name: 'Target User',
        email: 'target@example.com',
        tenantId: 'tenant-id',
        message: 'Roles assigned successfully',
      };

      jest.spyOn(adminService, 'updateUserRole').mockResolvedValue(mockUpdateResult);

      const result = await controller.updateUserRole(mockUpdateUserRoleDto, mockRequest);

      expect(adminService.updateUserRole).toHaveBeenCalledWith(mockUpdateUserRoleDto, 'user-id');
      expect(result).toEqual(mockUpdateResult);
    });
  });

  describe('Security Validation and Logging', () => {
    it('should log security events for user role updates', async () => {
      const mockUpdateUserRoleDto = {
        userId: 'target-user-id',
        tenantId: 'tenant-id',
        operation: 'ASSIGN',
        roles: [{ roleId: 'role-1' }],
        reason: 'Security audit',
      };

      const mockUpdateResult = {
        id: 'target-user-id',
        name: 'Target User',
        email: 'target@example.com',
        tenantId: 'tenant-id',
        message: 'Roles assigned successfully',
      };

      jest.spyOn(adminService, 'updateUserRole').mockResolvedValue(mockUpdateResult);

      await controller.updateUserRole(mockUpdateUserRoleDto, mockRequest);

      // Verify both attempt and success events were logged
      expect(eventLogService.logEvent).toHaveBeenCalledWith('USER_PROFILE_UPDATE', expect.objectContaining({
        metadata: expect.objectContaining({
          action: 'UPDATE_USER_ROLE_ATTEMPT',
        }),
        severity: 'SECURITY',
      }));

      expect(eventLogService.logEvent).toHaveBeenCalledWith('USER_PROFILE_UPDATE', expect.objectContaining({
        metadata: expect.objectContaining({
          action: 'UPDATE_USER_ROLE_SUCCESS',
        }),
        severity: 'SECURITY',
      }));
    });

    it('should handle role update with UUID format IDs', async () => {
      const mockUpdateUserRoleDto = {
        userId: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
        tenantId: 'f0e9d8c7-b6a5-4321-fedc-ba9876543210',
        operation: 'ASSIGN',
        roles: [{ roleId: 'c0b9a8d7-e6f5-4321-fedc-ba9876543210' }],
        reason: 'UUID format test',
      };

      const mockUpdateResult = {
        id: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
        name: 'UUID User',
        email: 'uuid@example.com',
        tenantId: 'f0e9d8c7-b6a5-4321-fedc-ba9876543210',
        message: 'Roles assigned successfully',
      };

      jest.spyOn(adminService, 'updateUserRole').mockResolvedValue(mockUpdateResult);

      const result = await controller.updateUserRole(mockUpdateUserRoleDto, mockRequest);

      expect(adminService.updateUserRole).toHaveBeenCalledWith(mockUpdateUserRoleDto, 'user-id');
      expect(result).toEqual(mockUpdateResult);
    });

    it('should handle role update with complex operation metadata', async () => {
      const mockUpdateUserRoleDto = {
        userId: 'target-user-id',
        tenantId: 'tenant-id',
        operation: 'ASSIGN',
        roles: [
          { 
            roleId: 'role-1', 
            validFrom: new Date().toISOString(), 
            validUntil: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString() 
          },
        ],
        reason: 'Time-based role assignment',
        grantedBy: 'system-admin',
        notifyUser: true,
        bypassHierarchyCheck: false,
        activationStrategy: 'scheduled',
      };

      const mockUpdateResult = {
        id: 'target-user-id',
        name: 'Target User',
        email: 'target@example.com',
        tenantId: 'tenant-id',
        message: 'Roles assigned successfully',
      };

      jest.spyOn(adminService, 'updateUserRole').mockResolvedValue(mockUpdateResult);

      const result = await controller.updateUserRole(mockUpdateUserRoleDto, mockRequest);

      expect(adminService.updateUserRole).toHaveBeenCalledWith(mockUpdateUserRoleDto, 'user-id');
      expect(result).toEqual(mockUpdateResult);
    });
  });

  describe('Security Edge Cases', () => {
    it('should handle role update with empty roles array', async () => {
      const mockUpdateUserRoleDto = {
        userId: 'target-user-id',
        tenantId: 'tenant-id',
        operation: 'ASSIGN',
        roles: [], // empty roles
        reason: 'Empty roles test',
      };

      const mockUpdateResult = {
        id: 'target-user-id',
        name: 'Target User',
        email: 'target@example.com',
        tenantId: 'tenant-id',
        message: 'Roles assigned successfully',
      };

      jest.spyOn(adminService, 'updateUserRole').mockResolvedValue(mockUpdateResult);

      const result = await controller.updateUserRole(mockUpdateUserRoleDto, mockRequest);

      expect(adminService.updateUserRole).toHaveBeenCalledWith(mockUpdateUserRoleDto, 'user-id');
      expect(result).toEqual(mockUpdateResult);
    });

    it('should handle role update with very long reason text', async () => {
      const longReason = 'A'.repeat(1000); // 1000 character reason
      const mockUpdateUserRoleDto = {
        userId: 'target-user-id',
        tenantId: 'tenant-id',
        operation: 'ASSIGN',
        roles: [{ roleId: 'role-1' }],
        reason: longReason,
      };

      const mockUpdateResult = {
        id: 'target-user-id',
        name: 'Target User',
        email: 'target@example.com',
        tenantId: 'tenant-id',
        message: 'Roles assigned successfully',
      };

      jest.spyOn(adminService, 'updateUserRole').mockResolvedValue(mockUpdateResult);

      const result = await controller.updateUserRole(mockUpdateUserRoleDto, mockRequest);

      expect(adminService.updateUserRole).toHaveBeenCalledWith(mockUpdateUserRoleDto, 'user-id');
      expect(result).toEqual(mockUpdateResult);
    });
  });
});