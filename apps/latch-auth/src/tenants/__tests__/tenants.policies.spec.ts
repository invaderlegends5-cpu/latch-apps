// src/tenants/__tests__/tenants.policies.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { PrismaService } from '../../prisma/prisma.service';
import { EventLogService } from '../../events/event.service';
import { TenantsService } from '../tenants.service';
import { UpdateTenantDto } from '../dto/update-tenant.dto';
import { BadRequestException, NotFoundException } from '@nestjs/common';
import { Redis } from 'ioredis';

// Define types for clarity if not already exported
type PolicyUpdateInput = Pick<UpdateTenantDto, 'policies' | 'security' | 'requireMFA'>;

describe('TenantsService - Policy Update Logic (Unit)', () => {
  let service: TenantsService;
  let prismaService: PrismaService;
  let eventLogService: EventLogService;
  let redisService: jest.Mocked<Redis>;

  // Define mock tenant object
  const mockTenant = {
    id: 'tenant-123',
    slug: 'acme-corp',
    name: 'Acme Corp',
    status: 'ACTIVE',
    createdAt: new Date(),
    updatedAt: new Date(),
    branding: {},
  };

  // Define a mock policy object
  const mockExistingPolicy = {
    id: 'policy-123',
    tenantId: mockTenant.id,
    requireMFA: true,
    privilegedUserMFARequired: true,
    roleInheritanceEnabled: true,
    permissionConflictStrategy: 'DENY_WINS' as const,
    allowedFactors: ['SMS', 'TOTP'],
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  // Define a mock updated policy object
  const mockUpdatedPolicy = {
    ...mockExistingPolicy,
    requireMFA: false,
    privilegedUserMFARequired: false,
    roleInheritanceEnabled: false,
    permissionConflictStrategy: 'ALLOW_WINS' as const,
    allowedFactors: ['TOTP'],
    updatedAt: new Date(Date.now() + 1000), // New update time
  };

  // Define mock stats for getTenantStats if called
  const mockStats = {
    userCount: 10,
    sessionCount: 5,
    roleCount: 3,
    permissionCount: 7,
    eventCount: 100,
    securityEventCount: 5,
  };

  beforeEach(async () => {
    // Create manual mock objects that match the working test pattern
    const mockRedis = {
      get: jest.fn(),
      setex: jest.fn(),
      del: jest.fn(),
    } as unknown as jest.Mocked<Redis>;

    const mockEventLogService = {
      logEvent: jest.fn(),
    };

    const mockPrismaService = {
      tenant: {
        findUnique: jest.fn(),
        update: jest.fn(),
        count: jest.fn(),
      },
      tenantPolicy: {
        upsert: jest.fn(),
        findUnique: jest.fn(),
      },
      event: {
        create: jest.fn(),
      },
      $transaction: jest.fn().mockImplementation(async (callback) => {
        // Create a transaction object with the same structure as main prisma
        const tx = {
          tenant: mockPrismaService.tenant,
          tenantPolicy: mockPrismaService.tenantPolicy,
          event: mockPrismaService.event,
        };
        return await callback(tx);
      }),
    } as unknown as PrismaService;

    const moduleRef: TestingModule = await Test.createTestingModule({
      providers: [
        TenantsService,
        {
          provide: PrismaService,
          useValue: mockPrismaService,
        },
        {
          provide: EventLogService,
          useValue: mockEventLogService,
        },
        {
          provide: 'REDIS',
          useValue: mockRedis,
        },
      ],
    }).compile();

    service = moduleRef.get<TenantsService>(TenantsService);
    prismaService = moduleRef.get<PrismaService>(PrismaService);
    eventLogService = moduleRef.get<EventLogService>(EventLogService);
    redisService = moduleRef.get('REDIS') as jest.Mocked<Redis>;

    // Clear all mocks before each test
    jest.clearAllMocks();
  });

  describe('update - Policy Logic', () => {
    it('should call tenantPolicy.upsert with correct data when only policies.requireMFA is provided', async () => {
      // Arrange
      const slug = 'acme-corp';
      const updatedBy = 'user-updater';
      const updateDto: PolicyUpdateInput = {
        policies: {
          requireMFA: false, // Change from true to false
        },
        // No 'security' or direct 'requireMFA' flag
      };

      // Mock tenant existence
      (prismaService.tenant.findUnique as jest.Mock).mockResolvedValue(mockTenant);
      // Mock existing policy (for upsert 'update' path)
      (prismaService.tenantPolicy.findUnique as jest.Mock).mockResolvedValue(mockExistingPolicy);
      // Mock the upsert to return the updated policy
      (prismaService.tenantPolicy.upsert as jest.Mock).mockResolvedValue(mockUpdatedPolicy);
      // Mock the tenant update (main part of update)
      (prismaService.tenant.update as jest.Mock).mockResolvedValue({ ...mockTenant, updatedAt: new Date() });

      // Act
      await service.update(slug, updateDto, updatedBy);

      // Assert
      // Check if tenantPolicy.upsert was called
      expect(prismaService.tenantPolicy.upsert).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { tenantId: mockTenant.id },
          update: {
            requireMFA: false, // The value from updateDto.policies.requireMFA
          },
          create: expect.any(Object), // Creation data structure, not the focus of this test
        })
      );

      // Specifically, check if requireMFA was part of the update call
      const upsertCallArgs = (prismaService.tenantPolicy.upsert as jest.Mock).mock.calls[0][0];
      expect(upsertCallArgs.update).toMatchObject({
        requireMFA: false,
      });
      // Ensure other policy fields were not touched by this specific DTO
      expect(upsertCallArgs.update).not.toHaveProperty('privilegedUserMFARequired');
      expect(upsertCallArgs.update).not.toHaveProperty('roleInheritanceEnabled');
      // ... check other fields not in DTO.policies

      // Check that main tenant update happened
      expect(prismaService.tenant.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { slug },
          data: expect.any(Object), // Main tenant data updates
        })
      );
    });

    it('should call tenantPolicy.upsert with correct data when security settings are provided', async () => {
      // Arrange
      const slug = 'acme-corp';
      const updatedBy = 'user-updater';
      const updateDto: PolicyUpdateInput = {
        security: {
          enforcePasswordComplexity: true,
          passwordMinLength: 12,
          maxFailedLoginAttempts: 5,
        },
        // No 'policies' or direct 'requireMFA' flag
      };

      // Mock tenant existence
      (prismaService.tenant.findUnique as jest.Mock).mockResolvedValue(mockTenant);
      // Mock existing policy (for upsert 'update' path)
      (prismaService.tenantPolicy.findUnique as jest.Mock).mockResolvedValue(mockExistingPolicy);
      // Mock the upsert to return the updated policy reflecting security changes
      const expectedPolicyUpdate = {
        ...mockExistingPolicy,
        enforcePasswordComplexity: true,
        passwordMinLength: 12,
        maxFailedLoginAttempts: 5,
        updatedAt: new Date(Date.now() + 1000),
      };
      (prismaService.tenantPolicy.upsert as jest.Mock).mockResolvedValue(expectedPolicyUpdate);
      // Mock the tenant update (main part of update)
      (prismaService.tenant.update as jest.Mock).mockResolvedValue({ ...mockTenant, updatedAt: new Date() });

      // Act
      await service.update(slug, updateDto, updatedBy);

      // Assert
      expect(prismaService.tenantPolicy.upsert).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { tenantId: mockTenant.id },
          update: expect.objectContaining({
            enforcePasswordComplexity: true,
            passwordMinLength: 12,
            maxFailedLoginAttempts: 5,
          }),
          create: expect.any(Object),
        })
      );

      // Check that main tenant update happened
      expect(prismaService.tenant.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { slug },
          data: expect.any(Object),
        })
      );
    });

    it('should call tenantPolicy.upsert with correct data when direct requireMFA flag is provided (takes precedence over policies.requireMFA)', async () => {
      // Arrange
      const slug = 'acme-corp';
      const updatedBy = 'user-updater';
      const updateDto: PolicyUpdateInput = {
        // 'policies.requireMFA' is false
        policies: { requireMFA: false },
        // BUT 'requireMFA' flag is true -> should take precedence
        requireMFA: true,
      };

      // Mock tenant existence
      (prismaService.tenant.findUnique as jest.Mock).mockResolvedValue(mockTenant);
      // Mock existing policy (for upsert 'update' path)
      (prismaService.tenantPolicy.findUnique as jest.Mock).mockResolvedValue(mockExistingPolicy);
      // Mock the upsert to return the updated policy reflecting the direct flag
      const expectedPolicyUpdate = {
        ...mockExistingPolicy,
        requireMFA: true, // Should be true due to direct flag
        updatedAt: new Date(Date.now() + 1000),
      };
      (prismaService.tenantPolicy.upsert as jest.Mock).mockResolvedValue(expectedPolicyUpdate);
      // Mock the tenant update (main part of update)
      (prismaService.tenant.update as jest.Mock).mockResolvedValue({ ...mockTenant, updatedAt: new Date() });

      // Act
      await service.update(slug, updateDto, updatedBy);

      // Assert
      expect(prismaService.tenantPolicy.upsert).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { tenantId: mockTenant.id },
          update: expect.objectContaining({
            requireMFA: true, // Takes precedence over policies.requireMFA
          }),
          create: expect.any(Object),
        })
      );

      // Check that main tenant update happened
      expect(prismaService.tenant.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { slug },
          data: expect.any(Object),
        })
      );
    });

    it('should call tenantPolicy.upsert with correct data when policies, security, and direct flags are provided (merging logic)', async () => {
      // Arrange
      const slug = 'acme-corp';
      const updatedBy = 'user-updater';
      const updateDto: PolicyUpdateInput = {
        policies: {
          requireMFA: false, // Would be overridden by direct flag below
          privilegedUserMFARequired: false,
          roleInheritanceEnabled: false,
        },
        security: {
          enforcePasswordComplexity: true,
          passwordMinLength: 14,
          maxFailedLoginAttempts: 3,
        },
        requireMFA: true, // Takes precedence over policies.requireMFA
      };

      // Mock tenant existence
      (prismaService.tenant.findUnique as jest.Mock).mockResolvedValue(mockTenant);
      // Mock existing policy (for upsert 'update' path)
      (prismaService.tenantPolicy.findUnique as jest.Mock).mockResolvedValue(mockExistingPolicy);
      // Mock the upsert to return the updated policy reflecting the merged changes
      const expectedPolicyUpdate = {
        ...mockExistingPolicy,
        requireMFA: true, // From direct flag
        privilegedUserMFARequired: false, // From policies
        roleInheritanceEnabled: false, // From policies
        enforcePasswordComplexity: true, // From security
        passwordMinLength: 14, // From security
        maxFailedLoginAttempts: 3, // From security
        updatedAt: new Date(Date.now() + 1000),
      };
      (prismaService.tenantPolicy.upsert as jest.Mock).mockResolvedValue(expectedPolicyUpdate);
      // Mock the tenant update (main part of update)
      (prismaService.tenant.update as jest.Mock).mockResolvedValue({ ...mockTenant, updatedAt: new Date() });

      // Act
      await service.update(slug, updateDto, updatedBy);

      // Assert
      expect(prismaService.tenantPolicy.upsert).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { tenantId: mockTenant.id },
          update: expect.objectContaining({
            requireMFA: true, // Direct flag wins
            privilegedUserMFARequired: false, // From policies
            roleInheritanceEnabled: false, // From policies
            enforcePasswordComplexity: true, // From security
            passwordMinLength: 14, // From security
            maxFailedLoginAttempts: 3, // From security
          }),
          create: expect.any(Object),
        })
      );

      // Check that main tenant update happened
      expect(prismaService.tenant.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { slug },
          data: expect.any(Object),
        })
      );
    });

    it('should NOT call tenantPolicy.upsert if neither policies, security, nor direct policy flags are provided in DTO', async () => {
      // Arrange
      const slug = 'acme-corp';
      const updatedBy = 'user-updater';
      const updateDto: Omit<PolicyUpdateInput, 'policies' | 'security' | 'requireMFA'> = {
        // Only non-policy related fields, for example:
        name: 'New Name',
      } as any; // Cast to allow omitting other required fields for this specific test

      // Mock tenant existence
      (prismaService.tenant.findUnique as jest.Mock).mockResolvedValue(mockTenant);
      // Mock the tenant update (main part of update)
      const updatedTenantResult = { ...mockTenant, name: 'New Name', updatedAt: new Date() };
      (prismaService.tenant.update as jest.Mock).mockResolvedValue(updatedTenantResult);

      // Act
      const result = await service.update(slug, updateDto, updatedBy);

      // Assert
      // The main tenant update should happen
      expect(prismaService.tenant.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { slug },
          data: expect.objectContaining({ name: 'New Name' }), // Only non-policy data updated
        })
      );
      // tenantPolicy.upsert should NOT have been called because no policy-related fields were in the DTO
      expect(prismaService.tenantPolicy.upsert).not.toHaveBeenCalled();

      // Result should be the updated tenant (without policy details necessarily, depending on service.select)
      expect(result).toEqual(updatedTenantResult);
    });

    // Optional: Test error handling within the policy update block if the service catches Prisma errors
    // and re-throws them as BadRequestException (as seen in the pasted service code).
    // This would involve mocking prismaService.tenantPolicy.upsert to reject with an error.
    // it('should handle Prisma errors during policy update and throw BadRequestException', async () => { ... });
  });

  // Optional: If the service has a dedicated helper function for merging/building policy data
  // from the DTO, that helper function could be tested separately here.
  // describe('buildPolicyUpdateData', () => { ... });

});