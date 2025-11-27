// src/tenants/__tests__/tenants.controller.unit.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import { mock, mockClear } from 'jest-mock-extended';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../../prisma/prisma.service';
import { EventLogService } from '../../events/event.service';
import { TenantsController } from '../tenants.controller';
import { TenantsService } from '../tenants.service';
import { CreateTenantDto, TenantStatusEnum, PermissionConflictStrategy, AllowedFactor } from '../dto/create-tenant.dto';
import { UpdateTenantDto } from '../dto/update-tenant.dto';
import { BadRequestException, ForbiddenException, InternalServerErrorException, NotFoundException } from '@nestjs/common';
import { IPReputationService } from '@/ip-reputation/ip-reputation.service';
import { RateLimitingService } from '@/rate-limiting/rate-limiting.service';

// Define types for request object structure used in tests
interface MockUser {
  id: string;
  sub: string;
  tenantId?: string;
  [key: string]: any; // Allow other properties
}

interface MockTenant {
  id: string;
  slug: string;
  name: string;
  status: string;
  [key: string]: any; // Allow other properties
}

interface MockRequest {
  user?: MockUser;
  tenant?: MockTenant;
  ip: string;
  headers: {
    [key: string]: string | string[] | undefined;
  };
  cookies?: {
    [key: string]: string;
  };
  [key: string]: any; // Allow other properties
}

describe('TenantsController (Unit)', () => {
  let controller: TenantsController;
  let tenantsService: jest.Mocked<TenantsService>;
  let eventLogService: jest.Mocked<EventLogService>;
  let configService: jest.Mocked<ConfigService>;
  let prismaService: jest.Mocked<PrismaService>; // Mocked for Prisma dependencies if controller had any direct calls (it doesn't in this impl, but good to have if guards were somehow involved in unit test setup)

  // Define mock request objects
  const mockSuperAdminUser: MockUser = {
    id: 'user-id-super-admin',
    sub: 'user-super-admin',
    tenantId: 'system-tenant', // SUPER_ADMIN might not have a specific tenant, or could have a 'system' tenant
  };
  const mockSuperAdminTenant: MockTenant = {
    id: 'system-tenant',
    slug: 'system-tenant',
    name: 'System Tenant',
    status: 'ACTIVE',
  };
  const mockSuperAdminRequest: MockRequest = {
    user: mockSuperAdminUser,
    tenant: mockSuperAdminTenant, // Assuming SUPER_ADMIN acts within a 'system' context
    ip: '192.168.1.100',
    headers: {
      'user-agent': 'test-agent-super-admin',
      'x-csrf-token': 'valid-csrf-token-super-admin',
    },
    cookies: {
      latch_session: 'session-id-super-admin',
      latch_csrf: 'valid-csrf-token-super-admin',
    },
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
    headers: {
      'user-agent': 'test-agent-admin',
      'x-csrf-token': 'valid-csrf-token-admin',
    },
    cookies: {
      latch_session: 'session-id-admin',
      latch_csrf: 'valid-csrf-token-admin',
    },
  };

  // Define DTOs
  const validCreateDto: CreateTenantDto = {
    name: 'New Tenant',
    slug: 'new-tenant',
    status: TenantStatusEnum.ACTIVE,
    branding: {
      logoUrl: 'https://example.com/logo.png',
      primaryColor: '#FF0000',
      secondaryColor: '#00FF00',
      companyName: 'New Company Name',
    },
    requireMFA: true,
    defaultRoleName: 'DefaultRole',
    security: {
      privilegedUserMFARequired: true,
      roleInheritanceEnabled: true,
      permissionConflictStrategy: PermissionConflictStrategy.DENY_WINS,
      allowedFactors: [AllowedFactor.SMS, AllowedFactor.TOTP],
      enforcePasswordComplexity: true,
      passwordMinLength: 8,
      passwordExpiryDate: '2026-01-01T00:00:00.000Z',
      maxFailedLoginAttempts: 3,
      lockoutDurationSeconds: 300,
    },
  };

  const validUpdateDto: UpdateTenantDto = {
    name: 'Updated Tenant Name',
    status: TenantStatusEnum.SUSPENDED,
    branding: {
      primaryColor: '#0000FF',
      companyName: 'Updated Company Name',
    },
    policies: {
      requireMFA: false,
      privilegedUserMFARequired: false,
    },
    security: {
      enforcePasswordComplexity: false,
    },
    requireMFA: false, // Direct flag
  };

  // Define mock results
  const mockTenantResult = {
    id: 'new-tenant-id',
    name: 'New Tenant',
    slug: 'new-tenant',
    status: 'ACTIVE',
    createdAt: new Date(),
    updatedAt: new Date(),
    branding: {
      logoUrl: 'https://example.com/logo.png',
      primaryColor: '#FF0000',
      secondaryColor: '#00FF00',
      companyName: 'New Company Name',
    },
  };

  const mockPaginatedResult = {
    data: [mockTenantResult],
    meta: {
      page: 1,
      limit: 50,
      total: 1,
      pages: 1,
    },
  };

  const mockStatsResult = {
    userCount: 10,
    sessionCount: 5,
    roleCount: 3,
    permissionCount: 7,
    eventCount: 100,
    securityEventCount: 5,
  };

  // Mock objects
  const mockTenantsService = mock<TenantsService>();
  const mockEventLogService = mock<EventLogService>();
  const mockConfigService = mock<ConfigService>();
  const mockPrismaService = mock<PrismaService>();
  const mockRateLimitingService = mock<RateLimitingService>();
  const mockIPReputationService = mock<IPReputationService>();
  
  beforeEach(async () => {
    const moduleRef: TestingModule = await Test.createTestingModule({
      controllers: [TenantsController],
      providers: [
        {
          provide: TenantsService,
          useValue: mockTenantsService,
        },
        {
          provide: EventLogService,
          useValue: mockEventLogService,
        },
        {
          provide: ConfigService,
          useValue: mockConfigService,
        },
        {
          provide: PrismaService,
          useValue: mockPrismaService, // Provided for completeness if needed by guards (though they shouldn't run in unit test for controller method call)
        },
        {
          provide: RateLimitingService,
          useValue: mockRateLimitingService,
        },
        {
          provide: IPReputationService,
          useValue: mockIPReputationService,
        },
      ],
    }).compile();

    controller = moduleRef.get<TenantsController>(TenantsController);
    tenantsService = moduleRef.get(TenantsService) as jest.Mocked<TenantsService>;
    eventLogService = moduleRef.get(EventLogService) as jest.Mocked<EventLogService>;
    configService = moduleRef.get(ConfigService) as jest.Mocked<ConfigService>;
    prismaService = moduleRef.get(PrismaService) as jest.Mocked<PrismaService>;

    // Clear all mocks before each test
    jest.clearAllMocks();
  });

  afterEach(() => {
    // Clean up any lingering state if necessary
    mockClear(mockTenantsService);
    mockClear(mockEventLogService);
    mockClear(mockConfigService);
    mockClear(mockPrismaService);
    mockClear(mockRateLimitingService);
    mockClear(mockIPReputationService);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('findAll', () => {
    it('should call tenantsService.findAll with correct parameters and return paginated result', async () => {
      // Arrange
      const page = 1;
      const limit = 50;
      const includeCounts = false;
      (mockTenantsService.findAll as jest.Mock).mockResolvedValue(mockPaginatedResult);

      // Act
      const result = await controller.findAll(page.toString(), limit.toString(), includeCounts.toString(), mockSuperAdminRequest as any);

      // Assert
      expect(tenantsService.findAll).toHaveBeenCalledWith(page, limit, includeCounts);
      expect(result).toEqual(mockPaginatedResult);
      expect(eventLogService.logEvent).toHaveBeenCalledWith('USER_LIST_ATTEMPTED', expect.objectContaining({
        userId: mockSuperAdminUser.sub,
        tenantId: mockSuperAdminTenant.id,
        metadata: expect.objectContaining({ action: 'LIST_TENANTS', page, limit, includeCounts }),
      }));
      expect(eventLogService.logEvent).toHaveBeenCalledWith('USER_LIST_ACCESSED', expect.objectContaining({
        userId: mockSuperAdminUser.sub,
        tenantId: mockSuperAdminTenant.id,
        metadata: expect.objectContaining({ action: 'LIST_TENANTS', total: mockPaginatedResult.meta.total }),
      }));
    });

    it('should validate pagination parameters and log security error', async () => {
      // Arrange
      const invalidPage = '0';
      const invalidLimit = '101';

      // Act & Assert
      await expect(
        controller.findAll(invalidPage, invalidLimit, 'false', mockSuperAdminRequest as any)
      ).rejects.toThrow(BadRequestException);

      expect(eventLogService.logEvent).toHaveBeenCalledWith('TENANT_VALIDATION_ERROR', expect.objectContaining({
        userId: mockSuperAdminUser.sub,
        tenantId: mockSuperAdminTenant.id,
        metadata: expect.objectContaining({ reason: 'invalid_pagination_params' }),
      }));
      expect(tenantsService.findAll).not.toHaveBeenCalled();
    });

    it('should handle service returning undefined gracefully', async () => {
      // Arrange
      (mockTenantsService.findAll as jest.Mock).mockResolvedValue(undefined);

      // Act & Assert
      await expect(
        controller.findAll('1', '50', 'false', mockSuperAdminRequest as any)
      ).rejects.toThrow(InternalServerErrorException);

      expect(tenantsService.findAll).toHaveBeenCalledWith(1, 50, false);
      expect(eventLogService.logEvent).toHaveBeenCalledWith('USER_LIST_ATTEMPTED', expect.any(Object));
      expect(eventLogService.logEvent).toHaveBeenCalledWith('INTERNAL_ERROR', expect.objectContaining({
        metadata: expect.objectContaining({ action: 'LIST_TENANTS', reason: 'invalid_service_response' }),
      }));
    });
  });

  describe('create', () => {
    it('should call tenantsService.create with correct parameters and return result', async () => {
      // Arrange
      (mockTenantsService.create as jest.Mock).mockResolvedValue(mockTenantResult);

      // Act
      const result = await controller.create(validCreateDto, mockSuperAdminRequest as any);

      // Assert
      expect(tenantsService.create).toHaveBeenCalledWith(validCreateDto, mockSuperAdminUser.sub);
      expect(result).toEqual(mockTenantResult);
      expect(eventLogService.logEvent).toHaveBeenCalledWith('USER_PROFILE_UPDATE', expect.objectContaining({
        userId: mockSuperAdminUser.sub,
        metadata: expect.objectContaining({ action: 'TENANT_CREATION_ATTEMPT', tenantSlug: validCreateDto.slug }),
      }));
      expect(eventLogService.logEvent).toHaveBeenCalledWith('AUDIT_TRAIL_ACCESSED', expect.objectContaining({
        userId: mockSuperAdminUser.sub,
        tenantId: mockTenantResult.id,
        metadata: expect.objectContaining({ action: 'CREATE_TENANT', tenantSlug: validCreateDto.slug }),
      }));
    });

    it('should handle service returning undefined gracefully', async () => {
      // Arrange
      (mockTenantsService.create as jest.Mock).mockResolvedValue(undefined);

      // Act & Assert
      await expect(
        controller.create(validCreateDto, mockSuperAdminRequest as any)
      ).rejects.toThrow(InternalServerErrorException);

      expect(tenantsService.create).toHaveBeenCalledWith(validCreateDto, mockSuperAdminUser.sub);
      expect(eventLogService.logEvent).toHaveBeenCalledWith('USER_PROFILE_UPDATE', expect.any(Object)); // Attempt log
      expect(eventLogService.logEvent).toHaveBeenCalledWith('INTERNAL_ERROR', expect.objectContaining({
        userId: mockSuperAdminUser.sub,
        metadata: expect.objectContaining({ action: 'CREATE_TENANT', reason: 'invalid_service_response' }),
      }));
    });
  });

  describe('findOne', () => {
    it('should call tenantsService.findOne with correct parameters and return result', async () => {
      // Arrange
      const slug = 'acme-corp';
      const includeStats = 'false';
      const expectedResult = { ...mockTenantResult, slug }; // Adjust based on what findOne returns
      (mockTenantsService.findOne as jest.Mock).mockResolvedValue(expectedResult);

      // Act
      const result = await controller.findOne(slug, includeStats, mockAdminRequest as any);

      // Assert
      expect(tenantsService.findOne).toHaveBeenCalledWith(slug, false); // includeStats parsed to boolean
      expect(result).toEqual(expectedResult);
      expect(eventLogService.logEvent).toHaveBeenCalledWith('USER_DATA_ACCESSED', expect.objectContaining({
        userId: mockAdminUser.sub,
        tenantId: expectedResult.id, // From the service result
        metadata: expect.objectContaining({ action: 'GET_TENANT', tenantSlug: slug, includeStats: false }),
      }));
    });

    it('should validate slug format and throw BadRequestException', async () => {
      // Arrange
      const invalidSlug = 'invalid@slug';

      // Act & Assert
      await expect(
        controller.findOne(invalidSlug, 'false', mockAdminRequest as any)
      ).rejects.toThrow(BadRequestException);

      expect(eventLogService.logEvent).toHaveBeenCalledWith('TENANT_VALIDATION_ERROR', expect.objectContaining({
        userId: mockAdminUser.sub,
        tenantId: mockAdminTenant.id,
        metadata: expect.objectContaining({ reason: 'invalid_slug_format' }),
      }));
      expect(tenantsService.findOne).not.toHaveBeenCalled();
    });

    it('should enforce tenant isolation and throw ForbiddenException (unit test for internal check)', async () => {
      // Arrange
      const requestedSlug = 'other-tenant'; // Different from req.tenant.slug ('acme-corp')
      // Note: In a *unit* test calling controller.findOne directly, the TenantGuard does not run.
      // If the controller *itself* has an internal check like `if (req.tenant?.slug !== slug)`,
      // it would run here. However, looking at the provided controller code, the isolation check
      // `if (req.tenant?.slug !== slug)` is present in `findOne`. This test verifies that logic.
      // The request object mockAdminRequest has req.tenant.slug = 'acme-corp'.
      // Calling findOne with 'other-tenant' should trigger the ForbiddenException from the controller's internal check.

      // Act & Assert
      await expect(
        controller.findOne(requestedSlug, 'false', mockAdminRequest as any) // req.tenant.slug ('acme-corp') !== requested slug ('other-tenant')
      ).rejects.toThrow(ForbiddenException);

      expect(eventLogService.logEvent).toHaveBeenCalledWith('TENANT_MISMATCH', expect.objectContaining({
        userId: mockAdminUser.sub,
        tenantId: mockAdminTenant.id,
        metadata: expect.objectContaining({ reason: 'unauthorized_tenant_access' }),
      }));
      expect(tenantsService.findOne).not.toHaveBeenCalled(); // Should not reach service call
    });

    it('should handle service returning undefined gracefully', async () => {
      // Arrange
      const slug = 'acme-corp';
      (mockTenantsService.findOne as jest.Mock).mockResolvedValue(undefined);

      // Act & Assert
      await expect(
        controller.findOne(slug, 'false', mockAdminRequest as any)
      ).rejects.toThrow(InternalServerErrorException);

      expect(tenantsService.findOne).toHaveBeenCalledWith(slug, false);
      expect(eventLogService.logEvent).toHaveBeenCalledWith('INTERNAL_ERROR', expect.objectContaining({
        userId: mockAdminUser.sub,
        tenantId: mockAdminTenant.id, // From req.tenant
        metadata: expect.objectContaining({ action: 'GET_TENANT', reason: 'invalid_service_response' }),
      }));
    });
  });

  describe('update', () => {
    it('should call tenantsService.update with correct parameters and return result', async () => {
      // Arrange
      const slug = 'acme-corp';
      (mockTenantsService.update as jest.Mock).mockResolvedValue(mockTenantResult);

      // Act
      const result = await controller.update(slug, validUpdateDto, mockAdminRequest as any);

      // Assert
      expect(tenantsService.update).toHaveBeenCalledWith(slug, validUpdateDto, mockAdminUser.sub);
      expect(result).toEqual(mockTenantResult);
      expect(eventLogService.logEvent).toHaveBeenCalledWith('USER_PROFILE_UPDATE', expect.objectContaining({
        userId: mockAdminUser.sub,
        tenantId: mockAdminTenant.id,
        metadata: expect.objectContaining({ action: 'TENANT_UPDATE_ATTEMPT', tenantSlug: slug }),
      }));
      expect(eventLogService.logEvent).toHaveBeenCalledWith('USER_PROFILE_UPDATE', expect.objectContaining({
        userId: mockAdminUser.sub,
        tenantId: mockTenantResult.id, // From the service result
        metadata: expect.objectContaining({ action: 'UPDATE_TENANT', tenantSlug: slug }),
      }));
    });

    it('should validate slug format and throw BadRequestException', async () => {
      // Arrange
      const invalidSlug = 'invalid@slug';

      // Act & Assert
      await expect(
        controller.update(invalidSlug, validUpdateDto, mockAdminRequest as any)
      ).rejects.toThrow(BadRequestException);

      expect(eventLogService.logEvent).toHaveBeenCalledWith('TENANT_VALIDATION_ERROR', expect.objectContaining({
        userId: mockAdminUser.sub,
        tenantId: mockAdminTenant.id,
        metadata: expect.objectContaining({ reason: 'invalid_slug_format' }),
      }));
      expect(tenantsService.update).not.toHaveBeenCalled();
    });

    it('should enforce tenant isolation and throw ForbiddenException (unit test for internal check)', async () => {
      // Arrange
      const requestedSlug = 'other-tenant'; // Different from req.tenant.slug ('acme-corp')

      // Act & Assert
      await expect(
        controller.update(requestedSlug, validUpdateDto, mockAdminRequest as any) // req.tenant.slug ('acme-corp') !== requested slug ('other-tenant')
      ).rejects.toThrow(ForbiddenException);

      expect(eventLogService.logEvent).toHaveBeenCalledWith('TENANT_MISMATCH', expect.objectContaining({
        userId: mockAdminUser.sub,
        tenantId: mockAdminTenant.id,
        metadata: expect.objectContaining({ reason: 'unauthorized_tenant_update' }),
      }));
      expect(tenantsService.update).not.toHaveBeenCalled(); // Should not reach service call
    });

    it('should handle service returning undefined gracefully', async () => {
      // Arrange
      const slug = 'acme-corp';
      (mockTenantsService.update as jest.Mock).mockResolvedValue(undefined);

      // Act & Assert
      await expect(
        controller.update(slug, validUpdateDto, mockAdminRequest as any)
      ).rejects.toThrow(InternalServerErrorException);

      expect(tenantsService.update).toHaveBeenCalledWith(slug, validUpdateDto, mockAdminUser.sub);
      expect(eventLogService.logEvent).toHaveBeenCalledWith('USER_PROFILE_UPDATE', expect.any(Object)); // Attempt log
      expect(eventLogService.logEvent).toHaveBeenCalledWith('INTERNAL_ERROR', expect.objectContaining({
        userId: mockAdminUser.sub,
        tenantId: mockAdminTenant.id, // From req.tenant
        metadata: expect.objectContaining({ action: 'UPDATE_TENANT', reason: 'invalid_service_response' }),
      }));
    });
  });

  describe('remove', () => {
    it('should call tenantsService.remove with correct parameters and return result', async () => {
      // Arrange
      const slug = 'acme-corp';
      (mockTenantsService.remove as jest.Mock).mockResolvedValue(mockTenantResult);

      // Act
      const result = await controller.remove(slug, mockSuperAdminRequest as any);

      // Assert
      expect(tenantsService.remove).toHaveBeenCalledWith(slug, mockSuperAdminUser.sub);
      expect(result).toEqual(mockTenantResult);
      expect(eventLogService.logEvent).toHaveBeenCalledWith('SESSION_REVOKE_ALL', expect.objectContaining({
        userId: mockSuperAdminUser.sub,
        tenantId: mockTenantResult.id, // From the service result
        metadata: expect.objectContaining({ action: 'DEACTIVATE_TENANT', tenantSlug: slug }),
      }));
    });

    it('should validate slug format and throw BadRequestException', async () => {
      // Arrange
      const invalidSlug = 'invalid@slug';

      // Act & Assert
      await expect(
        controller.remove(invalidSlug, mockSuperAdminRequest as any)
      ).rejects.toThrow(BadRequestException);

      expect(eventLogService.logEvent).toHaveBeenCalledWith('TENANT_VALIDATION_ERROR', expect.objectContaining({
        userId: mockSuperAdminUser.sub,
        tenantId: mockSuperAdminTenant.id,
        metadata: expect.objectContaining({ reason: 'invalid_slug_format' }),
      }));
      expect(tenantsService.remove).not.toHaveBeenCalled();
    });

    // NOTE: The tenant isolation check (req.tenant?.slug !== slug) is performed by TenantGuard *before*
    // the controller method runs. In a *unit* test calling controller.remove directly,
    // TenantGuard does not execute. Therefore, the internal isolation check within the controller
    // (if any existed *inside* the remove method after guards) would be relevant here.
    // However, the provided controller code for `remove` does *not* have an internal isolation check
    // like `findOne` or `update` do. The isolation is handled by TenantGuard.
    // This test cannot verify the guard's logic.

    it('should handle service returning undefined gracefully', async () => {
      // Arrange
      const slug = 'acme-corp';
      (mockTenantsService.remove as jest.Mock).mockResolvedValue(undefined);

      // Act & Assert
      await expect(
        controller.remove(slug, mockSuperAdminRequest as any)
      ).rejects.toThrow(InternalServerErrorException);

      expect(tenantsService.remove).toHaveBeenCalledWith(slug, mockSuperAdminUser.sub);
      expect(eventLogService.logEvent).toHaveBeenCalledWith('INTERNAL_ERROR', expect.objectContaining({
        userId: mockSuperAdminUser.sub,
        // tenantId is null or determined from input context for deletion
        metadata: expect.objectContaining({ action: 'DEACTIVATE_TENANT', reason: 'invalid_service_response' }),
      }));
    });
  });

  describe('getStats', () => {
    it('should call tenantsService.getTenantStats with correct parameters and return result', async () => {
      // Arrange
      const slug = 'acme-corp';
      (mockTenantsService.getTenantStats as jest.Mock).mockResolvedValue(mockStatsResult);

      // Act
      const result = await controller.getStats(slug, mockAdminRequest as any);

      // Assert
      expect(tenantsService.getTenantStats).toHaveBeenCalledWith(slug);
      expect(result).toEqual(mockStatsResult);
      expect(eventLogService.logEvent).toHaveBeenCalledWith('AUDIT_TRAIL_ACCESSED', expect.objectContaining({
        userId: mockAdminUser.sub,
        tenantId: mockAdminTenant.id, // From req.tenant
        metadata: expect.objectContaining({ action: 'GET_TENANT_STATS', tenantSlug: slug }),
      }));
    });

    it('should validate slug format and throw BadRequestException', async () => {
      // Arrange
      const invalidSlug = 'invalid@slug';

      // Act & Assert
      await expect(
        controller.getStats(invalidSlug, mockAdminRequest as any)
      ).rejects.toThrow(BadRequestException);

      expect(eventLogService.logEvent).toHaveBeenCalledWith('TENANT_VALIDATION_ERROR', expect.objectContaining({
        userId: mockAdminUser.sub,
        tenantId: mockAdminTenant.id,
        metadata: expect.objectContaining({ reason: 'invalid_slug_format' }),
      }));
      expect(tenantsService.getTenantStats).not.toHaveBeenCalled();
    });

    it('should enforce tenant isolation and throw ForbiddenException (unit test for internal check)', async () => {
      // Arrange
      const requestedSlug = 'other-tenant'; // Different from req.tenant.slug ('acme-corp')

      // Act & Assert
      await expect(
        controller.getStats(requestedSlug, mockAdminRequest as any) // req.tenant.slug ('acme-corp') !== requested slug ('other-tenant')
      ).rejects.toThrow(ForbiddenException);

      expect(eventLogService.logEvent).toHaveBeenCalledWith('AUDIT_TRAIL_ACCESS_ATTEMPTED', expect.objectContaining({
        userId: mockAdminUser.sub,
        tenantId: mockAdminTenant.id,
        metadata: expect.objectContaining({ reason: 'unauthorized_stats_access' }),
      }));
      expect(tenantsService.getTenantStats).not.toHaveBeenCalled(); // Should not reach service call
    });

    it('should handle service returning undefined gracefully', async () => {
      // Arrange
      const slug = 'acme-corp';
      (mockTenantsService.getTenantStats as jest.Mock).mockResolvedValue(undefined);

      // Act & Assert
      await expect(
        controller.getStats(slug, mockAdminRequest as any)
      ).rejects.toThrow(InternalServerErrorException);

      expect(tenantsService.getTenantStats).toHaveBeenCalledWith(slug);
      expect(eventLogService.logEvent).toHaveBeenCalledWith('INTERNAL_ERROR', expect.objectContaining({
        userId: mockAdminUser.sub,
        tenantId: mockAdminTenant.id, // From req.tenant
        metadata: expect.objectContaining({ action: 'GET_TENANT_STATS', reason: 'invalid_service_response' }),
      }));
    });
  });

  describe('activate', () => {
    it('should call tenantsService.activate with correct parameters and return result', async () => {
      // Arrange
      const slug = 'suspended-tenant';
      (mockTenantsService.activate as jest.Mock).mockResolvedValue(mockTenantResult);

      // Act
      const result = await controller.activate(slug, mockSuperAdminRequest as any);

      // Assert
      expect(tenantsService.activate).toHaveBeenCalledWith(slug, mockSuperAdminUser.sub);
      expect(result).toEqual(mockTenantResult);
      expect(eventLogService.logEvent).toHaveBeenCalledWith('LOGIN', expect.objectContaining({
        userId: mockSuperAdminUser.sub,
        tenantId: mockTenantResult.id, // From the service result
        metadata: expect.objectContaining({ action: 'ACTIVATE_TENANT', tenantSlug: slug }),
      }));
    });

    it('should validate slug format and throw BadRequestException', async () => {
      // Arrange
      const invalidSlug = 'invalid@slug';

      // Act & Assert
      await expect(
        controller.activate(invalidSlug, mockSuperAdminRequest as any)
      ).rejects.toThrow(BadRequestException);

      expect(eventLogService.logEvent).toHaveBeenCalledWith('TENANT_VALIDATION_ERROR', expect.objectContaining({
        userId: mockSuperAdminUser.sub,
        tenantId: mockSuperAdminTenant.id,
        metadata: expect.objectContaining({ reason: 'invalid_slug_format' }),
      }));
      expect(tenantsService.activate).not.toHaveBeenCalled();
    });

    // NOTE: Similar to 'remove', the tenant isolation check for activate is likely handled by TenantGuard.
    // The controller method itself doesn't seem to have an internal check after guards in the provided code.

    it('should handle service returning undefined gracefully', async () => {
      // Arrange
      const slug = 'suspended-tenant';
      (mockTenantsService.activate as jest.Mock).mockResolvedValue(undefined);

      // Act & Assert
      await expect(
        controller.activate(slug, mockSuperAdminRequest as any)
      ).rejects.toThrow(InternalServerErrorException);

      expect(tenantsService.activate).toHaveBeenCalledWith(slug, mockSuperAdminUser.sub);
      expect(eventLogService.logEvent).toHaveBeenCalledWith('INTERNAL_ERROR', expect.objectContaining({
        userId: mockSuperAdminUser.sub,
        // tenantId is null or determined from input context for activation
        metadata: expect.objectContaining({ action: 'ACTIVATE_TENANT', reason: 'invalid_service_response' }),
      }));
    });
  });
});