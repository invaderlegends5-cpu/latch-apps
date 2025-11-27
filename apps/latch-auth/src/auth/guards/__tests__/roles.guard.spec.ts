import { Reflector } from '@nestjs/core';
import { Test, TestingModule } from '@nestjs/testing';
import { ForbiddenException } from '@nestjs/common';
import { RolesGuard } from '../roles.guard'; // Adjust path
import { PrismaService } from '../../../prisma/prisma.service'; // Adjust path
import { EventLogService } from '../../../events/event.service'; // Adjust path

// Mock PrismaService
const mockPrismaService = {
  userRole: {
    findMany: jest.fn(),
  },
};

// Mock EventLogService
const mockEventLogService = {
  logEvent: jest.fn(),
};

// Mock Reflector
const mockReflector = {
  getAllAndOverride: jest.fn(),
};

// Helper to create a mock request object
const createMockRequest = (user: any, tenantId?: string) => ({
  user,
  ip: '192.168.1.1',
  headers: { 'user-agent': 'test-agent' },
});

// Helper to create a mock ExecutionContext
// This mock must include getHandler, getClass, and switchToHttp
const createMockExecutionContext = (handler: any = {}, classType: any = {}) => ({
  getHandler: () => handler, // Return the handler object (can be a mock function)
  getClass: () => classType, // Return the class object
  switchToHttp: () => ({
    getRequest: () => ({}), // Return a request object if needed by the guard's internal logic, though we'll override req in the actual call
  }),
});

describe('RolesGuard', () => {
  let guard: RolesGuard;
  let prismaService: any;
  let eventLogService: any;
  let reflector: any;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RolesGuard,
        { provide: PrismaService, useValue: mockPrismaService },
        { provide: EventLogService, useValue: mockEventLogService },
        { provide: Reflector, useValue: mockReflector },
      ],
    }).compile();

    guard = module.get<RolesGuard>(RolesGuard);
    prismaService = module.get<PrismaService>(PrismaService);
    eventLogService = module.get<EventLogService>(EventLogService);
    reflector = module.get<Reflector>(Reflector);

    // Clear all mocks before each test
    jest.clearAllMocks();
  });

  describe('canActivate', () => {
    // Common handler and class for tests expecting roles to be defined
    const mockHandler = jest.fn();
    const mockClass = class MockController {};

    it('should allow access if no roles are required', async () => {
      // Arrange
      const mockRequest = createMockRequest({ sub: 'user-123' });
      (reflector.getAllAndOverride as jest.Mock).mockReturnValue(undefined); // No roles required
      const mockContext = createMockExecutionContext(mockHandler, mockClass);

      // Act
    //   const result = await guard.canActivate(mockContext);
      // Note: canActivate will try to get req.user from the context's request,
      // but since we're mocking switchToHttp().getRequest() to return an empty object internally,
      // and passing the user via a different route for the call, we need to adjust.
      // The guard gets req.user from context.switchToHttp().getRequest().
      // To control req.user, we need to make the context's getRequest return our mockRequest.
      // Let's adjust the mockContext helper to accept the request.
      const mockContextWithUser = {
        getHandler: () => mockHandler,
        getClass: () => mockClass,
        switchToHttp: () => ({
          getRequest: () => mockRequest, // Use the request with user data
        }),
      };

      // Re-run with the correct context
      const result = await guard.canActivate(mockContextWithUser);

      // Assert
      expect(result).toBe(true);
      expect(reflector.getAllAndOverride).toHaveBeenCalledWith('roles', [mockHandler, mockClass]); // Verify reflector call
      expect(prismaService.userRole.findMany).not.toHaveBeenCalled(); // Should not query Prisma if no roles required
    });

    it('should throw ForbiddenException if req.user is missing', async () => {
      // Arrange
      const mockRequest = createMockRequest(undefined); // No user
      (reflector.getAllAndOverride as jest.Mock).mockReturnValue(['ADMIN']);
      const mockContext = {
        getHandler: () => mockHandler,
        getClass: () => mockClass,
        switchToHttp: () => ({
          getRequest: () => mockRequest,
        }),
      };

      // Act & Assert
      await expect(
        guard.canActivate(mockContext)
      ).rejects.toThrow(ForbiddenException);

      expect(eventLogService.logEvent).toHaveBeenCalledWith('ROLE_ACCESS_DENIED', expect.objectContaining({
        userId: null,
        metadata: expect.objectContaining({ requiredRoles: ['ADMIN'], reason: 'missing_user_object' }),
      }));
    });

    it('should throw ForbiddenException if req.user.id (sub) is missing', async () => {
      // Arrange
      const mockRequest = createMockRequest({ name: 'John Doe' }); // User without sub or id
      (reflector.getAllAndOverride as jest.Mock).mockReturnValue(['ADMIN']);
      const mockContext = {
        getHandler: () => mockHandler,
        getClass: () => mockClass,
        switchToHttp: () => ({
          getRequest: () => mockRequest,
        }),
      };

      // Act & Assert
      await expect(
        guard.canActivate(mockContext)
      ).rejects.toThrow(ForbiddenException);

      expect(eventLogService.logEvent).toHaveBeenCalledWith('ROLE_ACCESS_DENIED', expect.objectContaining({
        userId: null,
        metadata: expect.objectContaining({ requiredRoles: ['ADMIN'], reason: 'missing_user_id' }),
      }));
    });

    it('should allow access if user has the required role (global scope)', async () => {
        // ... (previous arrange and act code remains the same)
        const mockRequest = createMockRequest({ sub: 'user-123', tenantId: null }); // Global role context
        (reflector.getAllAndOverride as jest.Mock).mockReturnValue(['ADMIN']);
        (prismaService.userRole.findMany as jest.Mock).mockResolvedValue([
          { role: { name: 'ADMIN' } },
          { role: { name: 'USER' } },
        ]);
        const mockContext = {
          getHandler: () => mockHandler,
          getClass: () => mockClass,
          switchToHttp: () => ({
            getRequest: () => mockRequest,
          }),
        };
  
        const result = await guard.canActivate(mockContext);
  
        // Assert
        expect(result).toBe(true);
        expect(prismaService.userRole.findMany).toHaveBeenCalledWith({
          where: { userId: 'user-123' }, // Should query without tenant scope
          include: { role: true },       // Add the include part
        });
        expect(eventLogService.logEvent).toHaveBeenCalledWith('ROLE_ACCESS_GRANTED', expect.objectContaining({
          userId: 'user-123',
          tenantId: null,
          metadata: expect.objectContaining({ requiredRoles: ['ADMIN'], grantedRoles: ['ADMIN', 'USER'] }),
        }));
      });
  
      it('should allow access if user has the required role (tenant-scoped)', async () => {
        // ... (previous arrange and act code remains the same)
        const mockRequest = createMockRequest({ sub: 'user-123', tenantId: 'tenant-456' });
        (reflector.getAllAndOverride as jest.Mock).mockReturnValue(['ADMIN']);
        (prismaService.userRole.findMany as jest.Mock).mockResolvedValue([
          { role: { name: 'ADMIN', tenantId: 'tenant-456' } }, // Role specific to tenant-456
        ]);
        const mockContext = {
          getHandler: () => mockHandler,
          getClass: () => mockClass,
          switchToHttp: () => ({
            getRequest: () => mockRequest,
          }),
        };
  
        const result = await guard.canActivate(mockContext);
  
        // Assert
        expect(result).toBe(true);
        expect(prismaService.userRole.findMany).toHaveBeenCalledWith({
          where: { userId: 'user-123', role: { tenantId: 'tenant-456' } }, // Should query with tenant scope
          include: { role: true }, // Add the include part
        });
        expect(eventLogService.logEvent).toHaveBeenCalledWith('ROLE_ACCESS_GRANTED', expect.objectContaining({
          userId: 'user-123',
          tenantId: 'tenant-456',
          metadata: expect.objectContaining({ requiredRoles: ['ADMIN'], grantedRoles: ['ADMIN'] }),
        }));
      });
  
      it('should deny access if user does not have the required role (global scope)', async () => {
        // ... (previous arrange and act code remains the same)
        const mockRequest = createMockRequest({ sub: 'user-123', tenantId: null }); // Global context
        (reflector.getAllAndOverride as jest.Mock).mockReturnValue(['SUPER_ADMIN']);
        (prismaService.userRole.findMany as jest.Mock).mockResolvedValue([
          { role: { name: 'ADMIN' } }, // User has ADMIN, not SUPER_ADMIN
          { role: { name: 'USER' } },
        ]);
        const mockContext = {
          getHandler: () => mockHandler,
          getClass: () => mockClass,
          switchToHttp: () => ({
            getRequest: () => mockRequest,
          }),
        };
  
        // Act & Assert
        await expect(
          guard.canActivate(mockContext)
        ).rejects.toThrow(ForbiddenException);
  
        expect(prismaService.userRole.findMany).toHaveBeenCalledWith({
          where: { userId: 'user-123' }, // Should query without tenant scope
          include: { role: true },       // Add the include part
        });
        expect(eventLogService.logEvent).toHaveBeenCalledWith('ROLE_ACCESS_DENIED', expect.objectContaining({
          userId: 'user-123',
          tenantId: null,
          metadata: expect.objectContaining({ requiredRoles: ['SUPER_ADMIN'], reason: 'role_mismatch' }),
        }));
      });
  
      it('should deny access if user does not have the required role (tenant-scoped)', async () => {
        // ... (previous arrange and act code remains the same)
        const mockRequest = createMockRequest({ sub: 'user-123', tenantId: 'tenant-456' });
        (reflector.getAllAndOverride as jest.Mock).mockReturnValue(['SUPER_ADMIN']);
        (prismaService.userRole.findMany as jest.Mock).mockResolvedValue([
          { role: { name: 'ADMIN', tenantId: 'tenant-456' } }, // User has ADMIN in tenant-456, not SUPER_ADMIN
        ]);
        const mockContext = {
          getHandler: () => mockHandler,
          getClass: () => mockClass,
          switchToHttp: () => ({
            getRequest: () => mockRequest,
          }),
        };
  
        // Act & Assert
        await expect(
          guard.canActivate(mockContext)
        ).rejects.toThrow(ForbiddenException);
  
        expect(prismaService.userRole.findMany).toHaveBeenCalledWith({
          where: { userId: 'user-123', role: { tenantId: 'tenant-456' } }, // Should query with tenant scope
          include: { role: true }, // Add the include part
        });
        expect(eventLogService.logEvent).toHaveBeenCalledWith('ROLE_ACCESS_DENIED', expect.objectContaining({
          userId: 'user-123',
          tenantId: 'tenant-456',
          metadata: expect.objectContaining({ requiredRoles: ['SUPER_ADMIN'], reason: 'role_mismatch' }),
        }));
      });
  
      it('should deny access if user has no roles', async () => {
        // ... (previous arrange and act code remains the same)
        const mockRequest = createMockRequest({ sub: 'user-123', tenantId: 'tenant-456' });
        (reflector.getAllAndOverride as jest.Mock).mockReturnValue(['ADMIN']);
        (prismaService.userRole.findMany as jest.Mock).mockResolvedValue([]); // User has no roles
        const mockContext = {
          getHandler: () => mockHandler,
          getClass: () => mockClass,
          switchToHttp: () => ({
            getRequest: () => mockRequest,
          }),
        };
  
        // Act & Assert
        await expect(
          guard.canActivate(mockContext)
        ).rejects.toThrow(ForbiddenException);
  
        expect(prismaService.userRole.findMany).toHaveBeenCalledWith({
          where: { userId: 'user-123', role: { tenantId: 'tenant-456' } }, // Should query with tenant scope (if tenantId present)
          include: { role: true }, // Add the include part
        });
        expect(eventLogService.logEvent).toHaveBeenCalledWith('ROLE_ACCESS_DENIED', expect.objectContaining({
          userId: 'user-123',
          tenantId: 'tenant-456',
          metadata: expect.objectContaining({ requiredRoles: ['ADMIN'], reason: 'role_mismatch' }),
        }));
      });

    it('should allow access if required role is a subset of user roles', async () => {
      // Arrange
      const mockRequest = createMockRequest({ sub: 'user-123', tenantId: 'tenant-456' });
      (reflector.getAllAndOverride as jest.Mock).mockReturnValue(['USER']); // Requires 'USER'
      (prismaService.userRole.findMany as jest.Mock).mockResolvedValue([
        { role: { name: 'ADMIN', tenantId: 'tenant-456' } }, // User has 'ADMIN' (implies 'USER' in some models, but here it's exact match)
        { role: { name: 'USER', tenantId: 'tenant-456' } },  // User also has 'USER'
      ]);
      const mockContext = {
        getHandler: () => mockHandler,
        getClass: () => mockClass,
        switchToHttp: () => ({
          getRequest: () => mockRequest,
        }),
      };

      // Act
      const result = await guard.canActivate(mockContext);

      // Assert
      expect(result).toBe(true);
      expect(eventLogService.logEvent).toHaveBeenCalledWith('ROLE_ACCESS_GRANTED', expect.objectContaining({
        userId: 'user-123',
        tenantId: 'tenant-456',
        metadata: expect.objectContaining({ requiredRoles: ['USER'], grantedRoles: ['ADMIN', 'USER'] }),
      }));
    });
  });
});