// src/tenants/__tests__/tenants.integration.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import { AppModule } from '../../app.module'; // Or a more specific module if tenants are isolated
import { TenantsController } from '../tenants.controller';
import { TenantsService } from '../tenants.service';
import { EventLogService } from '../../events/event.service';
import { PrismaService } from '../../prisma/prisma.service';
import { AllowedFactor, CreateTenantDto, PermissionConflictStrategy } from '../dto/create-tenant.dto';
import { UpdateTenantDto } from '../dto/update-tenant.dto';
import { TenantStatusEnum } from '../dto/create-tenant.dto';
import { BadRequestException, ForbiddenException, InternalServerErrorException, NotFoundException } from '@nestjs/common';
import { mockDeep, DeepMockProxy } from 'jest-mock-extended'; // Or your chosen mocking library
import { Redis } from 'ioredis';

// Define types for request object structure used in tests
interface MockUser {
  id: string;
  sub: string;
  tenantId?: string;
  [key: string]: any;
}

interface MockTenant {
  id: string;
  slug: string;
  name: string;
  status: string;
  [key: string]: any;
}

interface MockRequest {
  user?: MockUser;
  tenant?: MockTenant;
  ip: string;
  headers: { [key: string]: string | string[] | undefined };
  cookies?: {
    [key: string]: string;
  };
  [key: string]: any;
}

// Mock Data
const mockSuperAdminUser: MockUser = {
  id: 'user-id-super-admin',
  sub: 'user-super-admin',
  tenantId: 'system-tenant',
};
const mockSuperAdminTenant: MockTenant = {
  id: 'system-tenant',
  slug: 'system-tenant',
  name: 'System Tenant',
  status: 'ACTIVE',
};
const mockSuperAdminRequest: MockRequest = {
  user: mockSuperAdminUser,
  tenant: mockSuperAdminTenant,
  ip: '192.168.1.100',
  headers: { 'user-agent': 'test-agent-super-admin' },
  cookies: { latch_session: 'session-id-super-admin', latch_csrf: 'csrf-token-super-admin' },
};

const mockAdminUser: MockUser = {
  id: 'user-id-admin',
  sub: 'user-admin',
  tenantId: 'tenant-123',
};
const mockAdminTenant: MockTenant = {
  id: 'tenant-123',
  slug: 'acme-corp',
  name: 'Acme Corp',
  status: 'ACTIVE',
};
const mockAdminRequest: MockRequest = {
  user: mockAdminUser,
  tenant: mockAdminTenant,
  ip: '192.168.1.101',
  headers: { 'user-agent': 'test-agent-admin' },
  cookies: { latch_session: 'session-id-admin', latch_csrf: 'csrf-token-admin' },
};

const validCreateDto: CreateTenantDto = {
  name: 'New Integration Test Tenant',
  slug: 'new-integration-tenant',
  status: TenantStatusEnum.ACTIVE,
  branding: {
    logoUrl: 'https://secure.example.com/logo.png',
    primaryColor: '#007bff',
    companyName: 'Integration Test Co',
  },
  requireMFA: true,
  defaultRoleName: 'DefaultUser',
  security: {
    privilegedUserMFARequired: true,
    roleInheritanceEnabled: true,
    permissionConflictStrategy: PermissionConflictStrategy.DENY_WINS,
    allowedFactors: [AllowedFactor.SMS, AllowedFactor.TOTP],
  },
};

const validUpdateDto: UpdateTenantDto = {
  name: 'Updated Integration Tenant Name',
  branding: {
    primaryColor: '#dc3545', // Bootstrap danger color
  },
  policies: {
    requireMFA: false,
  },
  security: {
    enforcePasswordComplexity: false,
  },
};

const mockCreatedTenant = {
  id: 'new-tenant-id',
  name: 'New Integration Test Tenant',
  slug: 'new-integration-tenant',
  status: 'ACTIVE',
  createdAt: new Date(),
  updatedAt: new Date(),
  branding: {
    logoUrl: 'https://secure.example.com/logo.png',
    primaryColor: '#007bff',
    companyName: 'Integration Test Co',
  },
};

const mockUpdatedTenant = {
  id: 'tenant-123',
  name: 'Updated Integration Tenant Name',
  slug: 'acme-corp',
  status: 'ACTIVE',
  createdAt: new Date(),
  updatedAt: new Date(),
  branding: {
    logoUrl: 'https://secure.example.com/logo.png',
    primaryColor: '#dc3545',
    companyName: 'Acme Corp',
  },
};

describe('TenantsController-Service Integration Tests', () => {
  let controller: TenantsController;
  let service: DeepMockProxy<TenantsService>; // Use DeepMockProxy type for the service
  let prismaService: DeepMockProxy<PrismaService>;
  let eventLogService: DeepMockProxy<EventLogService>;
  let redisService: jest.Mocked<Redis>;

  // Mock objects - these are the mock instances to be injected
  const mockPrisma = mockDeep<PrismaService>();
  const mockEventLog = mockDeep<EventLogService>();
  const mockRedis = {
    get: jest.fn(),
    setex: jest.fn(),
    del: jest.fn(),
  } as unknown as jest.Mocked<Redis>;

  // Create a DeepMockProxy for the service itself
  const mockTenantsService = mockDeep<TenantsService>();

  beforeAll(async () => {
    const moduleRef: TestingModule = await Test.createTestingModule({
      imports: [AppModule], // Use the main app module or a specific tenants module if isolated
      // Override providers with mocks for external dependencies
    })
    .overrideProvider(PrismaService)
    .useValue({
      ...mockPrisma, // Include all the existing mockDeep functionality
      // ADD these models that the services use during initialization
      event: {
        findMany: jest.fn().mockResolvedValue([]), // For IPReputationService, BehavioralAnalysisService
        create: jest.fn(),
        findUnique: jest.fn(),
        findFirst: jest.fn(),
        count: jest.fn(),
      },
      tenant: {
        findMany: jest.fn(),
        findUnique: jest.fn(() => Promise.resolve({
          id: 'system-tenant',
          slug: 'system-tenant',
          name: 'System Tenant',
          status: 'ACTIVE',
          branding: {},
          createdAt: new Date(),
          updatedAt: new Date()
        })),
        count: jest.fn(() => Promise.resolve(10)),
        update: jest.fn(),
        delete: jest.fn(),
        
        // This 'create' mock definition is necessary to fix the TypeError:
        create: jest.fn((args: any) => {
          return Promise.resolve({
            id: 'new-tenant-id-' + Date.now(), 
            name: args.data.name,
            slug: args.data.slug,
            status: args.data.status || 'ACTIVE',
            branding: args.data.branding || {},
            createdAt: new Date(),
            updatedAt: new Date(),
          });
        }),
      },
      tenantRateLimitProfile: {
        findFirst: jest.fn().mockResolvedValue(null), // For RateLimitingService
        findMany: jest.fn().mockResolvedValue([]), // For RateLimitingService warmup
        create: jest.fn(),
        update: jest.fn(),
      },
      IPReputationService: {
          
            isIPBlocked: jest.fn().mockResolvedValue(false),
            getReputation: jest.fn().mockResolvedValue({ score: 0, riskLevel: 'LOW' }),
            // Add other methods if TenantGuard uses them
         
        },
      session: {
        findMany: jest.fn().mockResolvedValue([]), // For DeviceFingerprintingService
        findUnique: jest.fn(),
        findFirst: jest.fn(),
        create: jest.fn(),
        update: jest.fn(),
        count: jest.fn(),
      },
      iPBlock: {
        findFirst: jest.fn().mockResolvedValue(null),
        findMany: jest.fn().mockResolvedValue([]),
        upsert: jest.fn(),
        deleteMany: jest.fn(),
        create: jest.fn(),
        update: jest.fn(),
      },
      iPWhitelist: {
        findFirst: jest.fn().mockResolvedValue(null),
        findMany: jest.fn().mockResolvedValue([]),
        upsert: jest.fn(),
        deleteMany: jest.fn(),
      },
      // Add the $transaction mock that includes these models
      $transaction: jest.fn().mockImplementation(async (callback) => {
        const tx = {
          ...mockPrisma.$transaction,
          event: {
            findMany: jest.fn().mockResolvedValue([]),
            create: jest.fn(),
            findUnique: jest.fn(),
            findFirst: jest.fn(),
            count: jest.fn(),
          },
          tenantRateLimitProfile: {
            findFirst: jest.fn().mockResolvedValue(null),
            findMany: jest.fn().mockResolvedValue([]),
            create: jest.fn(),
            update: jest.fn(),
          },
          session: {
            findMany: jest.fn().mockResolvedValue([]),
            findUnique: jest.fn(),
            findFirst: jest.fn(),
            create: jest.fn(),
            update: jest.fn(),
            count: jest.fn(),
          },
          iPBlock: {
            findFirst: jest.fn().mockResolvedValue(null),
            findMany: jest.fn().mockResolvedValue([]),
            upsert: jest.fn(),
            deleteMany: jest.fn(),
            create: jest.fn(),
            update: jest.fn(),
          },
          iPWhitelist: {
            findFirst: jest.fn().mockResolvedValue(null),
            findMany: jest.fn().mockResolvedValue([]),
            upsert: jest.fn(),
            deleteMany: jest.fn(),
          },

        };
        return await callback(tx);
      }),
    })
    .overrideProvider(EventLogService)
    .useValue(mockEventLog)
    .overrideProvider('REDIS') // Use the injection token for Redis
    .useValue(mockRedis)
    .overrideProvider(TenantsService) // Override the actual service with the mock
    .useValue(mockTenantsService)
    .compile();
  
    const app: INestApplication = moduleRef.createNestApplication();
    await app.init();
  
    // Retrieve the *injected* instances, which are now the mocks
    controller = moduleRef.get<TenantsController>(TenantsController); // Controller is injected with the mock service
    service = moduleRef.get(TenantsService) as DeepMockProxy<TenantsService>; // This is now the mockTenantsService
    prismaService = moduleRef.get(PrismaService) as DeepMockProxy<PrismaService>;
    eventLogService = moduleRef.get(EventLogService) as DeepMockProxy<EventLogService>;
    redisService = moduleRef.get('REDIS') as jest.Mocked<Redis>;
  
    // Clear mocks before each test run within this suite
    jest.clearAllMocks();
  });

  afterAll(async () => {
    // await app.close(); // Not necessary if using Test.createTestingModule directly
  });

  describe('Controller handling Service Responses', () => {
    // These tests verify how the controller reacts to *different outcomes* from the *real* service call,
    // when the service's dependencies (like Prisma) are mocked.

    it('should return the service result when service.create returns a valid object', async () => {
      // Arrange: Mock the service method to return a valid tenant object
      mockTenantsService.create.mockResolvedValue(mockCreatedTenant);

      // Act: Call the controller method (simulating successful guard execution)
      const result = await controller.create(validCreateDto, mockSuperAdminRequest as any);

      // Assert: Controller should return the exact object returned by the service
      expect(result).toEqual(mockCreatedTenant);
      // Assert: Service was called with correct arguments
      expect(mockTenantsService.create).toHaveBeenCalledWith(validCreateDto, mockSuperAdminUser.sub);
      // Assert: Controller logged the success event (if applicable based on service return)
      expect(eventLogService.logEvent).toHaveBeenCalledWith('AUDIT_TRAIL_ACCESSED', expect.objectContaining({
         metadata: expect.objectContaining({ action: 'CREATE_TENANT' })
      }));
    });

    it('should throw InternalServerErrorException when service.create returns undefined', async () => {
      // Arrange: Mock the service method to return undefined
      mockTenantsService.create.mockResolvedValue(undefined);

      // Act & Assert: Controller should catch the undefined result and throw
      await expect(
        controller.create(validCreateDto, mockSuperAdminRequest as any)
      ).rejects.toThrow(InternalServerErrorException);

      // Assert: Service was called
      expect(mockTenantsService.create).toHaveBeenCalledWith(validCreateDto, mockSuperAdminUser.sub);
      // Assert: Controller logged the internal error
      expect(eventLogService.logEvent).toHaveBeenCalledWith('INTERNAL_ERROR', expect.objectContaining({
         metadata: expect.objectContaining({ action: 'CREATE_TENANT', reason: 'invalid_service_response' })
      }));
    });

    it('should return the service result when service.update returns a valid object', async () => {
      // Arrange: Mock the service method to return a valid tenant object
      mockTenantsService.update.mockResolvedValue(mockUpdatedTenant);

      // Act: Call the controller method (simulating successful guard execution)
      const result = await controller.update('acme-corp', validUpdateDto, mockAdminRequest as any);

      // Assert: Controller should return the exact object returned by the service
      expect(result).toEqual(mockUpdatedTenant);
      // Assert: Service was called with correct arguments
      expect(mockTenantsService.update).toHaveBeenCalledWith('acme-corp', validUpdateDto, mockAdminUser.sub);
      // Assert: Controller logged the success event (if applicable based on service return)
      expect(eventLogService.logEvent).toHaveBeenCalledWith('USER_PROFILE_UPDATE', expect.objectContaining({
         metadata: expect.objectContaining({ action: 'UPDATE_TENANT' })
      }));
    });

    it('should throw InternalServerErrorException when service.update returns undefined', async () => {
      // Arrange: Mock the service method to return undefined
      mockTenantsService.update.mockResolvedValue(undefined);

      // Act & Assert: Controller should catch the undefined result and throw
      await expect(
        controller.update('acme-corp', validUpdateDto, mockAdminRequest as any)
      ).rejects.toThrow(InternalServerErrorException);

      // Assert: Service was called
      expect(mockTenantsService.update).toHaveBeenCalledWith('acme-corp', validUpdateDto, mockAdminUser.sub);
      // Assert: Controller logged the internal error
      expect(eventLogService.logEvent).toHaveBeenCalledWith('INTERNAL_ERROR', expect.objectContaining({
         metadata: expect.objectContaining({ action: 'UPDATE_TENANT', reason: 'invalid_service_response' })
      }));
    });

    it('should return the service result when service.remove returns a valid object', async () => {
      // Arrange: Mock the service method to return a valid tenant object (representing the updated/suspended tenant)
      const mockRemovedTenant = { ...mockAdminTenant, status: 'SUSPENDED' };
      mockTenantsService.remove.mockResolvedValue(mockRemovedTenant);

      // Act: Call the controller method (simulating successful guard execution)
      const result = await controller.remove('acme-corp', mockSuperAdminRequest as any);

      // Assert: Controller should return the exact object returned by the service
      expect(result).toEqual(mockRemovedTenant);
      // Assert: Service was called with correct arguments
      expect(mockTenantsService.remove).toHaveBeenCalledWith('acme-corp', mockSuperAdminUser.sub);
      // Assert: Controller logged the success event (if applicable based on service return)
      expect(eventLogService.logEvent).toHaveBeenCalledWith('SESSION_REVOKE_ALL', expect.objectContaining({
         metadata: expect.objectContaining({ action: 'DEACTIVATE_TENANT' })
      }));
    });

    it('should throw InternalServerErrorException when service.remove returns undefined', async () => {
      // Arrange: Mock the service method to return undefined
      mockTenantsService.remove.mockResolvedValue(undefined);

      // Act & Assert: Controller should catch the undefined result and throw
      await expect(
        controller.remove('acme-corp', mockSuperAdminRequest as any)
      ).rejects.toThrow(InternalServerErrorException);

      // Assert: Service was called
      expect(mockTenantsService.remove).toHaveBeenCalledWith('acme-corp', mockSuperAdminUser.sub);
      // Assert: Controller logged the internal error
      expect(eventLogService.logEvent).toHaveBeenCalledWith('INTERNAL_ERROR', expect.objectContaining({
         metadata: expect.objectContaining({ action: 'DEACTIVATE_TENANT', reason: 'invalid_service_response' })
      }));
    });

    // Add similar tests for activate, findOne, getStats if they also have the undefined check
    // or other specific controller-level handling based on service output.

    it('should propagate errors thrown by the service (e.g., NotFoundException from service.findOne)', async () => {
        // Arrange:
        // 1. Mock the service method to throw an error
        const serviceError = new NotFoundException('Tenant not found by service');
        mockTenantsService.findOne.mockRejectedValue(serviceError);
  
        // 2. Create a request object that has passed tenant isolation checks by the guard.
        //    This means req.user.tenantId should match req.tenant.id for the slug being accessed.
        //    Since the test is for 'non-existent-tenant', we need to simulate the guard
        //    having found a tenant record (or set req.tenant) that belongs to the user.
        //    We can directly mock this state for the controller call.
        const mockRequestWithTenantAccess = {
          ...mockAdminRequest,
          tenant: { id: mockAdminUser.tenantId, slug: 'non-existent-tenant' } // Controller sees user's tenant ID for this slug
        };
  
        // Act & Assert: Controller should now call the service and let its error bubble up
        await expect(
          controller.findOne('non-existent-tenant', 'false', mockRequestWithTenantAccess as any)
        ).rejects.toThrow(NotFoundException); // Expect the specific error from the service
  
        // Assert: Service was called with correct arguments
        expect(mockTenantsService.findOne).toHaveBeenCalledWith('non-existent-tenant', false);
        // Note: Controller might or might not log this specific error depending on its implementation.
        // If it has a try/catch around the service call specifically for logging *before* re-throwing,
        // you could assert that log call too. But generally, letting the service error propagate is correct.
      });

    it('should propagate errors thrown by the service (e.g., BadRequestException from service.update)', async () => {
      // Arrange: Mock the service method to throw an error (e.g., due to validation within the service)
      const serviceError = new BadRequestException('Invalid update data provided to service');
      mockTenantsService.update.mockRejectedValue(serviceError);

      // Act & Assert: Controller should let the service's error bubble up
      await expect(
        controller.update('acme-corp', { name: 'Too@Short!' }, mockAdminRequest as any) // Assuming service validates name
      ).rejects.toThrow(BadRequestException); // Expect the specific error from the service

      // Assert: Service was called
      expect(mockTenantsService.update).toHaveBeenCalledWith('acme-corp', { name: 'Too@Short!' }, mockAdminUser.sub);
    });

  });

  // Optional: Describe block for testing complex controller-service workflows
  // if the controller orchestrates multiple service calls or has complex conditional logic
  // based on service responses.
  // describe('Complex Workflows', () => { ... });

});