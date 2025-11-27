// src/auth/__tests__/roles.guard.unit.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { Reflector } from '@nestjs/core';
import { ForbiddenException, UnauthorizedException } from '@nestjs/common';
import { RolesGuard } from '../guards/roles.guard'; // Adjust path if needed
import { PrismaService } from '../../prisma/prisma.service'; // Adjust path if needed
import { EventLogService } from '../../events/event.service'; // Adjust path if needed
import { ROLES_KEY } from '../decorators/roles.decorator'; // Adjust path if needed
import { mockDeep, DeepMockProxy } from 'jest-mock-extended'; // Or your chosen mocking library

// Define types for clarity if not already exported
type MockUser = {
  id: string;
  sub: string;
  tenantId?: string;
  [key: string]: any; // Allow other properties potentially added by JwtAuthGuard
};

type MockTenant = {
  id: string;
  slug: string;
  name: string;
  status: string;
  [key: string]: any; // Allow other properties
};

type MockRequest = {
  user?: MockUser;
  tenant?: MockTenant;
  ip: string;
  headers: { [key: string]: string | string[] | undefined };
  [key: string]: any; // Allow other properties
};

// Mock data
const mockSuperAdminUser: MockUser = {
  id: 'user-id-super-admin',
  sub: 'user-super-admin',
  tenantId: 'system-tenant', // Or null for system-level users
};
const mockAdminUser: MockUser = {
  id: 'user-id-admin',
  sub: 'user-admin',
  tenantId: 'tenant-123',
};
const mockRegularUser: MockUser = {
  id: 'user-id-regular',
  sub: 'user-regular',
  tenantId: 'tenant-123',
};
const mockTenant: MockTenant = {
  id: 'tenant-123',
  slug: 'acme-corp',
  name: 'Acme Corp',
  status: 'ACTIVE',
};

describe('RolesGuard (Unit)', () => {
  let guard: RolesGuard;
  let reflector: Reflector;
  let prismaService: DeepMockProxy<PrismaService>;
  let eventLogService: DeepMockProxy<EventLogService>;

  const mockReflector = mockDeep<Reflector>();
  const mockPrisma = mockDeep<PrismaService>();
  const mockEventLog = mockDeep<EventLogService>();

  beforeEach(async () => {
    const moduleRef: TestingModule = await Test.createTestingModule({
      providers: [
        RolesGuard,
        {
          provide: Reflector,
          useValue: mockReflector,
        },
        {
          provide: PrismaService,
          useValue: mockPrisma,
        },
        {
          provide: EventLogService,
          useValue: mockEventLog,
        },
      ],
    }).compile();

    guard = moduleRef.get<RolesGuard>(RolesGuard);
    reflector = moduleRef.get<Reflector>(Reflector);
    prismaService = moduleRef.get(PrismaService) as DeepMockProxy<PrismaService>;
    eventLogService = moduleRef.get(EventLogService) as DeepMockProxy<EventLogService>;

    jest.clearAllMocks(); // Clear all mocks before each test
  });

  describe('canActivate', () => {
    it('should allow access if no required roles are specified', async () => {
      // Arrange
      const mockContext = {
        getHandler: jest.fn(),
        getClass: jest.fn(),
        switchToHttp: () => ({
          getRequest: () => ({}), // Request object not relevant for this specific check
        }),
      };
      (reflector.getAllAndOverride as jest.Mock).mockReturnValue(undefined); // No roles required

      // Act
      const result = await guard.canActivate(mockContext as any);

      // Assert
      expect(result).toBe(true);
      expect(reflector.getAllAndOverride).toHaveBeenCalledWith(ROLES_KEY, [mockContext.getHandler(), mockContext.getClass()]);
      expect(prismaService.userRole.findMany).not.toHaveBeenCalled(); // Should not query Prisma if no roles required
      expect(eventLogService.logEvent).not.toHaveBeenCalled(); // Should not log if no check was performed
    });

    it('should allow access if required roles are an empty array', async () => {
      // Arrange
      const mockContext = {
        getHandler: jest.fn(),
        getClass: jest.fn(),
        switchToHttp: () => ({
          getRequest: () => ({}), // Request object not relevant for this specific check
        }),
      };
      (reflector.getAllAndOverride as jest.Mock).mockReturnValue([]); // Empty array of roles required

      // Act
      const result = await guard.canActivate(mockContext as any);

      // Assert
      expect(result).toBe(true);
      expect(reflector.getAllAndOverride).toHaveBeenCalledWith(ROLES_KEY, [mockContext.getHandler(), mockContext.getClass()]);
      expect(prismaService.userRole.findMany).not.toHaveBeenCalled(); // Should not query Prisma if no roles required
      expect(eventLogService.logEvent).not.toHaveBeenCalled(); // Should not log if no check was performed
    });

    it('should throw ForbiddenException if user has no roles matching required roles', async () => {
      // Arrange
      const requiredRoles = ['SUPER_ADMIN'];
      const mockRequest: MockRequest = {
        user: mockAdminUser, // User has 'ADMIN' role (we'll mock this)
        ip: '192.168.1.100',
        headers: { 'user-agent': 'test-agent-admin' },
      };
      const mockContext = {
        getHandler: jest.fn(),
        getClass: jest.fn(),
        switchToHttp: () => ({
          getRequest: () => mockRequest,
        }),
      };

      (reflector.getAllAndOverride as jest.Mock).mockReturnValue(requiredRoles); // Requires 'SUPER_ADMIN'

      // Mock Prisma call: User has 'ADMIN' role in 'tenant-123', not 'SUPER_ADMIN'
      (prismaService.userRole.findMany as jest.Mock).mockResolvedValue([
        { role: { name: 'ADMIN', isSystem: false, tenantId: 'tenant-123' } }
      ]);

      // Act & Assert
      await expect(guard.canActivate(mockContext as any)).rejects.toThrow(ForbiddenException);

      // Verify Prisma was called with the correct arguments based on the request user
      expect(prismaService.userRole.findMany).toHaveBeenCalledWith({
        where: {
          userId: mockAdminUser.sub, // Uses req.user.sub
          role: { tenantId: mockAdminUser.tenantId }, // Filters roles by user's tenantId
        },
        include: { role: true },
      });

      // Verify that the failure was logged
      expect(eventLogService.logEvent).toHaveBeenCalledWith('ROLE_ACCESS_DENIED', expect.objectContaining({
         userId: mockAdminUser.sub,
         tenantId: mockAdminUser.tenantId,
         metadata: expect.objectContaining({
           requiredRoles,
           reason: 'role_mismatch', // Or whatever the specific reason is logged as in your code
         }),
         severity: 'SECURITY',
      }));
    });

    it('should allow access if user has a role matching one of the required roles', async () => {
      // Arrange
      const requiredRoles = ['ADMIN', 'SUPER_ADMIN']; // Requires 'ADMIN' OR 'SUPER_ADMIN'
      const mockRequest: MockRequest = {
        user: mockAdminUser, // User has 'ADMIN' role (we'll mock this)
        ip: '192.168.1.100',
        headers: { 'user-agent': 'test-agent-admin' },
      };
      const mockContext = {
        getHandler: jest.fn(),
        getClass: jest.fn(),
        switchToHttp: () => ({
          getRequest: () => mockRequest,
        }),
      };

      (reflector.getAllAndOverride as jest.Mock).mockReturnValue(requiredRoles);

      // Mock Prisma call: User has 'ADMIN' role in 'tenant-123'
      (prismaService.userRole.findMany as jest.Mock).mockResolvedValue([
        { role: { name: 'ADMIN', isSystem: false, tenantId: 'tenant-123' } }
      ]);

      // Act & Assert
      const result = await guard.canActivate(mockContext as any);

      // Verify Prisma was called
      expect(prismaService.userRole.findMany).toHaveBeenCalledWith({
        where: {
          userId: mockAdminUser.sub,
          role: { tenantId: mockAdminUser.tenantId },
        },
        include: { role: true },
      });

      // Verify result is true
      expect(result).toBe(true);

      // Verify success was logged
      expect(eventLogService.logEvent).toHaveBeenCalledWith('ROLE_ACCESS_GRANTED', expect.objectContaining({
         userId: mockAdminUser.sub,
         tenantId: mockAdminUser.tenantId,
         metadata: expect.objectContaining({
           requiredRoles,
           grantedRoles: ['ADMIN'], // Or the list of user's roles found
         }),
         severity: 'INFO',
      }));
    });

    it('should allow access if user has a system-level role (e.g., SUPER_ADMIN) matching required roles', async () => {
      // Arrange
      const requiredRoles = ['SUPER_ADMIN'];
      const mockRequest: MockRequest = {
        user: mockSuperAdminUser, // User has 'SUPER_ADMIN' role (we'll mock this)
        ip: '192.168.1.100',
        headers: { 'user-agent': 'test-agent-super-admin' },
      };
      const mockContext = {
        getHandler: jest.fn(),
        getClass: jest.fn(),
        switchToHttp: () => ({
          getRequest: () => mockRequest,
        }),
      };

      (reflector.getAllAndOverride as jest.Mock).mockReturnValue(requiredRoles);

      // Mock Prisma call: User has 'SUPER_ADMIN' role (isSystem: true)
      (prismaService.userRole.findMany as jest.Mock).mockResolvedValue([
        { role: { name: 'SUPER_ADMIN', isSystem: true, tenantId: 'system-tenant' } } // Or tenantId might be null for system roles
      ]);

      // Act & Assert
      const result = await guard.canActivate(mockContext as any);

      // Verify Prisma was called
      expect(prismaService.userRole.findMany).toHaveBeenCalledWith({
        where: {
          userId: mockSuperAdminUser.sub,
          // Note: The guard's query might filter by tenantId. If SUPER_ADMIN is a system role,
          // it might exist in a system tenant or not be tied to a specific tenant.
          // The mock below assumes it exists in 'system-tenant'. Adjust if the real query is different
          // (e.g., if system roles are fetched differently).
          // For now, let's assume the tenantId comes from the user object.
          // If SUPER_ADMIN role belongs to a 'system' tenant, the mock user should reflect that tenantId.
          // If the role is truly global (not tenant-scoped), the guard query might be different.
          // Based on the guard code, it seems tenant-scoped. So, mockSuperAdminUser.tenantId should match.
          // Let's assume mockSuperAdminUser.tenantId = 'system-tenant' for this test.
          // Adjust the mockUser object definition if needed.
          role: { tenantId: mockSuperAdminUser.tenantId }, // Filter by system tenant ID
        },
        include: { role: true },
      });

      // Verify result is true
      expect(result).toBe(true);

      // Verify success was logged
      expect(eventLogService.logEvent).toHaveBeenCalledWith('ROLE_ACCESS_GRANTED', expect.objectContaining({
         userId: mockSuperAdminUser.sub,
         tenantId: mockSuperAdminUser.tenantId, // Or null if system tenant concept is different
         metadata: expect.objectContaining({
           requiredRoles,
           grantedRoles: ['SUPER_ADMIN'],
         }),
         severity: 'INFO',
      }));
    });

    it('should throw ForbiddenException if user object is missing', async () => {
      // Arrange
      const requiredRoles = ['SUPER_ADMIN'];
      const mockRequest: MockRequest = {
        // No user object
        ip: '192.168.1.100',
        headers: { 'user-agent': 'test-agent-no-user' },
      };
      const mockContext = {
        getHandler: jest.fn(),
        getClass: jest.fn(),
        switchToHttp: () => ({
          getRequest: () => mockRequest,
        }),
      };

      (reflector.getAllAndOverride as jest.Mock).mockReturnValue(requiredRoles);

      // Act & Assert
      await expect(guard.canActivate(mockContext as any)).rejects.toThrow(ForbiddenException);

      // Prisma should NOT be called if req.user is missing
      expect(prismaService.userRole.findMany).not.toHaveBeenCalled();

      // Failure should be logged
      expect(eventLogService.logEvent).toHaveBeenCalledWith('ROLE_ACCESS_DENIED', expect.objectContaining({
         userId: null, // Or undefined
         tenantId: null, // Or undefined
         metadata: expect.objectContaining({
           requiredRoles,
           reason: 'missing_user_object', // Or whatever the specific reason is logged as
         }),
         severity: 'SECURITY',
      }));
    });

    it('should throw ForbiddenException if user object is not an object', async () => {
      // Arrange
      const requiredRoles = ['SUPER_ADMIN'];
      const mockRequest: MockRequest = {
        user: 'invalid-user-string', // User is a string, not an object
        ip: '192.168.1.100',
        headers: { 'user-agent': 'test-agent-invalid-user' },
      };
      const mockContext = {
        getHandler: jest.fn(),
        getClass: jest.fn(),
        switchToHttp: () => ({
          getRequest: () => mockRequest,
        }),
      };

      (reflector.getAllAndOverride as jest.Mock).mockReturnValue(requiredRoles);

      // Act & Assert
      await expect(guard.canActivate(mockContext as any)).rejects.toThrow(ForbiddenException);

      // Prisma should NOT be called if req.user is not an object
      expect(prismaService.userRole.findMany).not.toHaveBeenCalled();

      // Failure should be logged
      expect(eventLogService.logEvent).toHaveBeenCalledWith('ROLE_ACCESS_DENIED', expect.objectContaining({
         userId: null, // Because user was not an object
         tenantId: null,
         metadata: expect.objectContaining({
           requiredRoles,
           reason: 'missing_user_object', // The check is typeof user !== 'object'
         }),
         severity: 'SECURITY',
      }));
    });

    it('should throw ForbiddenException if user ID is missing from user object', async () => {
      // Arrange
      const requiredRoles = ['SUPER_ADMIN'];
      const mockRequest: MockRequest = {
        user: { tenantId: 'tenant-123' }, // User object exists but has no id/sub
        ip: '192.168.1.100',
        headers: { 'user-agent': 'test-agent-no-user-id' },
      };
      const mockContext = {
        getHandler: jest.fn(),
        getClass: jest.fn(),
        switchToHttp: () => ({
          getRequest: () => mockRequest,
        }),
      };

      (reflector.getAllAndOverride as jest.Mock).mockReturnValue(requiredRoles);

      // Act & Assert
      await expect(guard.canActivate(mockContext as any)).rejects.toThrow(ForbiddenException);

      // Prisma should NOT be called if userId cannot be extracted
      expect(prismaService.userRole.findMany).not.toHaveBeenCalled();

      // Failure should be logged
      expect(eventLogService.logEvent).toHaveBeenCalledWith('ROLE_ACCESS_DENIED', expect.objectContaining({
         userId: null, // Because id/sub was missing from user object
         tenantId: 'tenant-123', // Tenant ID was present
         metadata: expect.objectContaining({
           requiredRoles,
           reason: 'missing_user_id', // Or whatever the specific reason is logged as
         }),
         severity: 'SECURITY',
      }));
    });

    // Optional: Test error handling if Prisma throws an unexpected error during findMany
    // This depends on whether the guard catches and re-throws/loggs specific Prisma errors.
    // it('should handle Prisma errors gracefully and potentially throw an internal error', async () => { ... });

  });
});