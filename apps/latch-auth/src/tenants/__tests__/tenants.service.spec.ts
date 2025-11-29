//src/tenants/__tests/tenants.service.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { EventLogService } from '../../events/event.service';
import { TenantsService } from '../tenants.service';
import { PrismaService } from '../../prisma/prisma.service';
import { NotFoundException, BadRequestException, ForbiddenException } from '@nestjs/common';
import { Redis } from 'ioredis';
import { generateIntegrityHash } from '@/auth/utils/hash.util';


// Mock Redis
const mockRedis = {
  get: jest.fn(),
  setex: jest.fn(),
  del: jest.fn(),
};

// Mock EventLogService
const mockEventLogService = {
  logEvent: jest.fn(),
};


// Mock generateIntegrityHash
jest.mock('@/auth/utils/hash.util', () => ({
  generateIntegrityHash: jest.fn().mockReturnValue('mocked-hash'),
}));

describe('TenantsService', () => {
  let service: TenantsService;
  let prisma: PrismaService;
  let eventLogService: EventLogService;

  beforeEach(async () => {
    console.log("Creating TestingModule...");
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        TenantsService,
        {
          provide: PrismaService,
          useValue: {
            tenant: {
              findMany: jest.fn(),
              findUnique: jest.fn(),
              create: jest.fn(),
              update: jest.fn(),
              count: jest.fn(),
            },
            role: {
              create: jest.fn(),
              count: jest.fn(),
            },
            tenantPolicy: {
              create: jest.fn(),
              upsert: jest.fn(),
            },
            event: {
              create: jest.fn(),
              count: jest.fn(),
            },
            user: {
              count: jest.fn(),
              findMany: jest.fn().mockResolvedValue([]), // Return an empty array, not undefined
              findUnique: jest.fn(),
              create: jest.fn(),
              update: jest.fn(),
              delete: jest.fn(),
            },
            session: {
              count: jest.fn(),
              findMany: jest.fn().mockResolvedValue([]), // Return an empty array, not undefined
              findUnique: jest.fn(),
              create: jest.fn(),
              update: jest.fn(),
              updateMany: jest.fn().mockResolvedValue({ count: 0 }),
              delete: jest.fn(),
            },
            permission: {
              count: jest.fn(),
            },
            // Simple transaction mock that delegates to the main prisma instance
            // $transaction: jest.fn().mockImplementation(async (callback) => {
            //   return await callback(prisma);
            // }),

            $transaction: jest.fn().mockImplementation(async (cb) => cb({
              tenant: prisma.tenant,
              role: prisma.role,
              tenantPolicy: prisma.tenantPolicy,
              event: prisma.event,
              user: prisma.user,
              session: prisma.session,
              permission: prisma.permission,
            })),

          },
        },
        {
          provide: 'REDIS',
          useValue: mockRedis,
        },
        { 
          provide: EventLogService,
          useValue: mockEventLogService,
        },
      ],
    }).compile();

    console.log("TestingModule created:", !!module); // Logs true if module exists, false otherwise
    console.log("Getting TenantsService...");

    service = module.get<TenantsService>(TenantsService);

    console.log("TenantsService retrieved:", !!service);
    console.log("Getting PrismaService...");

    prisma = module.get<PrismaService>(PrismaService);

    console.log("PrismaService retrieved:", !!prisma); 

    eventLogService = module.get<EventLogService>(EventLogService);

    // Clear all mocks before each test
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('findAll', () => {
    it('should return cached results if available', async () => {
      const date = new Date();
      const cachedResult = {
        data: [
          {
            id: 'tenant1',
            name: 'Test Tenant',
            slug: 'test',
            status: 'ACTIVE',
            createdAt: new Date().toISOString(), // Use ISO string to match what Redis returns
            updatedAt: new Date().toISOString(),
            branding: null,
          },
        ],
        meta: {
          page: 1,
          limit: 50,
          total: 1,
          pages: 1,
        },
      };

      (mockRedis.get as jest.Mock).mockResolvedValue(JSON.stringify(cachedResult));

      const result = await service.findAll(1, 50, false);
      expect(result).toEqual(cachedResult);
      expect(mockRedis.get).toHaveBeenCalledWith('tenants:page:1:limit:50:counts:false');
    });

    it('should fetch from database and cache results if not cached', async () => {
      const date = new Date();
      const tenants = [
        {
          id: 'tenant1',
          name: 'Test Tenant',
          slug: 'test',
          status: 'ACTIVE',
          createdAt: date,
          updatedAt: date,
          branding: null,
        },
      ];

      (mockRedis.get as jest.Mock).mockResolvedValue(null);
      (prisma.tenant.findMany as jest.Mock).mockResolvedValue(tenants);
      (prisma.tenant.count as jest.Mock).mockResolvedValue(1);

      const result = await service.findAll(1, 50, false);

      expect(prisma.tenant.findMany).toHaveBeenCalledWith({
        skip: 0,
        take: 50,
        select: {
          id: true,
          name: true,
          slug: true,
          status: true,
          createdAt: true,
          updatedAt: true,
          branding: true,
        },
        orderBy: { createdAt: 'desc' },
      });

      expect(mockRedis.setex).toHaveBeenCalledWith(
        'tenants:page:1:limit:50:counts:false',
        300,
        JSON.stringify(result)
      );
    });

    it('should validate pagination parameters', async () => {
      await expect(service.findAll(0, 50)).rejects.toThrow(BadRequestException);
      await expect(service.findAll(1, 0)).rejects.toThrow(BadRequestException);
      await expect(service.findAll(1, 101)).rejects.toThrow(BadRequestException);
    });

    it('should include counts when requested', async () => {
      const date = new Date();
      const tenants = [
        {
          id: 'tenant1',
          name: 'Test Tenant',
          slug: 'test',
          status: 'ACTIVE',
          createdAt: date,
          updatedAt: date,
          branding: null,
        },
      ];

      (mockRedis.get as jest.Mock).mockResolvedValue(null);
      (prisma.tenant.findMany as jest.Mock).mockResolvedValue(tenants);
      (prisma.tenant.count as jest.Mock).mockResolvedValue(1);

      await service.findAll(1, 50, true);

      expect(prisma.tenant.findMany).toHaveBeenCalledWith({
        skip: 0,
        take: 50,
        select: {
          id: true,
          name: true,
          slug: true,
          status: true,
          createdAt: true,
          updatedAt: true,
          branding: true,
          _count: {
            select: {
              users: true,
              Role: true,
              Permission: true,
            },
          },
        },
        orderBy: { createdAt: 'desc' },
      });
    });
  });

  describe('findOne', () => {
    it('should return cached basic tenant if available', async () => {
      const date = new Date();
      const cachedTenant = {
        id: 'tenant1',
        name: 'Test Tenant',
        slug: 'test',
        status: 'ACTIVE',
        createdAt: date.toISOString(), // Use ISO string
        updatedAt: date.toISOString(),
        branding: null,
      };

      (mockRedis.get as jest.Mock).mockResolvedValue(JSON.stringify(cachedTenant));

      const result = await service.findOne('test', false);
      expect(result).toEqual(cachedTenant);
      expect(mockRedis.get).toHaveBeenCalledWith('tenant:test:basic');
    });

    it('should return cached tenant with data if available and includeStats is false', async () => {
      const date = new Date();
      const cachedTenant = {
        id: 'tenant1',
        name: 'Test Tenant',
        slug: 'test',
        status: 'ACTIVE',
        createdAt: date.toISOString(), // Use ISO string
        updatedAt: date.toISOString(),
        branding: null,
        users: [],
        policies: {},
        // Don't include Role and Permission arrays since Redis might not store them
      };
    
      (mockRedis.get as jest.Mock).mockResolvedValueOnce(null); // basic cache miss
      (mockRedis.get as jest.Mock).mockResolvedValue(JSON.stringify(cachedTenant));
    
      const result = await service.findOne('test', false);
      expect(result).toEqual(cachedTenant);
      expect(mockRedis.get).toHaveBeenCalledWith('tenant:test:with_data');
    });

    it('should fetch from database if not cached and cache the result', async () => {
      const date = new Date();
      const tenant = {
        id: 'tenant1',
        name: 'Test Tenant',
        slug: 'test',
        status: 'ACTIVE',
        createdAt: date,
        updatedAt: date,
        branding: null,
        users: [],
        policies: {},
        Role: [],
        Permission: [],
      };

      (mockRedis.get as jest.Mock).mockResolvedValue(null);
      (prisma.tenant.findUnique as jest.Mock).mockResolvedValue(tenant);

      const result = await service.findOne('test', false);

      expect(prisma.tenant.findUnique).toHaveBeenCalledWith({
        where: { slug: 'test' },
        include: {
          users: {
            select: {
              id: true,
              name: true,
              phone: true,
              email: true,
              isPhoneVerified: true,
              isEmailVerified: true,
              createdAt: true,
            },
            take: 50,
          },
          policies: {
            select: {
              requireMFA: true,
              privilegedUserMFARequired: true,
              roleInheritanceEnabled: true,
              permissionConflictStrategy: true,
              defaultRoleId: true,
              createdAt: true,
              updatedAt: true,
            },
          },
          Role: {
            select: {
              id: true,
              name: true,
              isSystem: true,
              _count: {
                select: { userRoles: true },
              },
            },
            take: 20,
          },
          Permission: {
            select: {
              id: true,
              name: true,
              resource: true,
              action: true,
              _count: {
                select: { rolePermissions: true },
              },
            },
            take: 50,
          },
        },
      });

      expect(mockRedis.setex).toHaveBeenCalledWith(
        'tenant:test:with_data',
        900,
        JSON.stringify(tenant)
      );
    });

    it('should return tenant with stats when includeStats is true', async () => {
      const date = new Date();
      const tenant = {
        id: 'tenant1',
        name: 'Test Tenant',
        slug: 'test',
        status: 'ACTIVE',
        createdAt: date,
        updatedAt: date,
        branding: null,
        users: [],
        policies: {},
        Role: [{ id: 'role1' }],
        Permission: [{ id: 'perm1' }],
      };

      (mockRedis.get as jest.Mock).mockResolvedValue(null);
      (prisma.tenant.findUnique as jest.Mock).mockResolvedValue(tenant);
      (prisma.user.count as jest.Mock).mockResolvedValue(10);
      (prisma.session.count as jest.Mock).mockResolvedValue(5);
      (prisma.event.count as jest.Mock).mockResolvedValue(20);

      const result = await service.findOne('test', true);

      expect(result.stats).toEqual({
        userCount: 10,
        sessionCount: 5,
        eventCount: 20,
        roleCount: 1,
        permissionCount: 1,
      });
    });

    it('should throw NotFoundException when tenant not found', async () => {
      (mockRedis.get as jest.Mock).mockResolvedValue(null);
      (prisma.tenant.findUnique as jest.Mock).mockResolvedValue(null);

      await expect(service.findOne('nonexistent')).rejects.toThrow(NotFoundException);
    });
    it('should cache and return cached stats when includeStats is true', async () => {
      const date = new Date();
      const tenant = {
        id: 'tenant1',
        name: 'Test Tenant',
        slug: 'test',
        status: 'ACTIVE',
        createdAt: date,
        updatedAt: date,
        branding: null,
        users: [],
        policies: {},
        Role: [{ id: 'role1' }],
        Permission: [{ id: 'perm1' }],
      };
    
      const stats = {
        userCount: 10,
        sessionCount: 5,
        eventCount: 20,
        roleCount: 1,
        permissionCount: 1,
      };
    
      // First call - should hit database and cache stats
      (mockRedis.get as jest.Mock)
        .mockResolvedValueOnce(null) // basic cache miss
        .mockResolvedValueOnce(null) // with_data cache miss
        .mockResolvedValueOnce(null); // stats cache miss
      
      (prisma.tenant.findUnique as jest.Mock).mockResolvedValue(tenant);
      (prisma.user.count as jest.Mock).mockResolvedValue(10);
      (prisma.session.count as jest.Mock).mockResolvedValue(5);
      (prisma.event.count as jest.Mock).mockResolvedValue(20);
    
      const result1 = await service.findOne('test', true);
    
      expect(result1.stats).toEqual(stats);
      expect(prisma.tenant.findUnique).toHaveBeenCalled();
      expect(prisma.user.count).toHaveBeenCalled();
      expect(prisma.session.count).toHaveBeenCalled();
      expect(prisma.event.count).toHaveBeenCalled();
      expect(mockRedis.setex).toHaveBeenCalledWith(
        'tenant:test:stats',
        300,
        JSON.stringify(stats)
      );
    
      // Reset mocks
      jest.clearAllMocks();
    
      // Second call - should hit stats cache
      const cachedStats = JSON.stringify(stats);
      (mockRedis.get as jest.Mock)
        .mockResolvedValueOnce(null) // basic cache miss
        .mockResolvedValueOnce(JSON.stringify(tenant)) // with_data cache hit
        .mockResolvedValueOnce(cachedStats); // stats cache hit
    
      const result2 = await service.findOne('test', true);
    
      expect(result2.stats).toEqual(stats);
      // Verify database queries were not called for stats
      expect(prisma.user.count).not.toHaveBeenCalled();
      expect(prisma.session.count).not.toHaveBeenCalled();
      expect(prisma.event.count).not.toHaveBeenCalled();
      // But tenant query might still be called depending on cache state
      expect(mockRedis.get).toHaveBeenCalledWith('tenant:test:stats');
    });
  });

  describe('create', () => {
    it('should create a tenant successfully', async () => {
      const createTenantDto = {
        name: 'New Tenant',
        slug: 'new-tenant',
        branding: {
          logoUrl: 'https://example.com/logo.png__',
          primaryColor: '#000000',
        },
        defaultRoleName: 'USER',
      };

      const date = new Date();
      const createdTenant = {
        id: 'tenant1',
        name: 'New Tenant',
        slug: 'new-tenant',
        status: 'ACTIVE',
        createdAt: date,
        updatedAt: date,
        branding: {
          logoUrl: 'https://example.com/logo.png__',
          primaryColor: '#000000',
        },
      };

      // Mock the Prisma methods that will be called within the transaction
      (prisma.tenant.findUnique as jest.Mock).mockResolvedValue(null);
      (prisma.tenant.create as jest.Mock).mockResolvedValue(createdTenant);
      (prisma.role.create as jest.Mock).mockResolvedValue({ id: 'role1' });
      (prisma.tenantPolicy.create as jest.Mock).mockResolvedValue({});
      (prisma.event.create as jest.Mock).mockResolvedValue({ id: 'event1' }); // Add this mock

      const result = await service.create(createTenantDto, 'user1');

      expect(result).toEqual(createdTenant);
      expect(prisma.tenant.create).toHaveBeenCalledWith({
        data: {
         name: 'New Tenant',
         slug: 'new-tenant',
         status: 'ACTIVE',
         branding: {
           logoUrl: 'https://example.com/logo.png__',
           primaryColor: '#000000',
         },
       },
       select: {
         id: true,
         name: true,
         slug: true,
         status: true,
         createdAt: true,
         updatedAt: true,
         branding: true,
       },
     });
    });

    it('should create a tenant with security settings', async () => {
      const createTenantDto = {
        name: 'New Tenant',
        slug: 'new-tenant',
        branding: {
          logoUrl: 'https://example.com/logo.png  ',
          primaryColor: '#000000',
        },
        defaultRoleName: 'USER',
        requireMFA: true,
        security: {
          privilegedUserMFARequired: false,
          roleInheritanceEnabled: false,
          permissionConflictStrategy: 'ALLOW_WINS',
          allowedFactors: ['TOTP', 'EMAIL'],
        },
      };
  
      const date = new Date();
      const createdTenant = {
        id: 'tenant1',
        name: 'New Tenant',
        slug: 'new-tenant',
        status: 'ACTIVE',
        createdAt: date,
        updatedAt: date,
        branding: {
          logoUrl: 'https://example.com/logo.png  ',
          primaryColor: '#000000',
        },
      };
  
      // Mock the Prisma methods that will be called within the transaction
      (prisma.tenant.findUnique as jest.Mock).mockResolvedValue(null);
      (prisma.tenant.create as jest.Mock).mockResolvedValue(createdTenant);
      (prisma.role.create as jest.Mock).mockResolvedValue({ id: 'role1' });
      (prisma.tenantPolicy.create as jest.Mock).mockResolvedValue({});
      (prisma.event.create as jest.Mock).mockResolvedValue({ id: 'event1' });
  
      const result = await service.create(createTenantDto, 'user1');
  
      expect(result).toEqual(createdTenant);
      // Verify that tenant policy was created with security settings
      expect(prisma.tenantPolicy.create).toHaveBeenCalledWith({
         data: {
          tenantId: createdTenant.id,
          requireMFA: true,
          defaultRoleId: 'role1', // This should be the ID from the role creation
          privilegedUserMFARequired: false,
          roleInheritanceEnabled: false,
          permissionConflictStrategy: 'ALLOW_WINS',
          allowedFactors: ['TOTP', 'EMAIL'],
        },
      });
    });
    it('should create a tenant with default role and link it to policy', async () => {
      const createTenantDto = {
        name: 'New Tenant',
        slug: 'new-tenant',
        branding: {
          logoUrl: 'https://example.com/logo.png  ',
          primaryColor: '#000000',
        },
        defaultRoleName: 'ADMIN', // This will trigger role creation
      };
    
      const date = new Date();
      const createdTenant = {
        id: 'tenant1',
        name: 'New Tenant',
        slug: 'new-tenant',
        status: 'ACTIVE',
        createdAt: date,
        updatedAt: date,
        branding: {
          logoUrl: 'https://example.com/logo.png  ',
          primaryColor: '#000000',
        },
      };
    
      // Mock the Prisma methods that will be called within the transaction
      (prisma.tenant.findUnique as jest.Mock).mockResolvedValue(null);
      (prisma.tenant.create as jest.Mock).mockResolvedValue(createdTenant);
      (prisma.role.create as jest.Mock).mockResolvedValue({ id: 'role123' }); // Mock role creation
      (prisma.tenantPolicy.create as jest.Mock).mockResolvedValue({});
      (prisma.event.create as jest.Mock).mockResolvedValue({ id: 'event1' });
    
      const result = await service.create(createTenantDto, 'user1');
    
      expect(result).toEqual(createdTenant);
      // Verify that role was created with proper data
      expect(prisma.role.create).toHaveBeenCalledWith({
         data: {
          name: 'ADMIN',
          tenantId: createdTenant.id, // Verify tenant ID is linked
          isSystem: true, // Verify it's marked as system role
          description: 'Default role assigned to new users',
        },
        select: {
          id: true,
        },
      });
      // Verify that tenant policy was created and links to the default role
      expect(prisma.tenantPolicy.create).toHaveBeenCalledWith({
         data: {
          tenantId: createdTenant.id,
          requireMFA: false, // Default value when requireMFA is undefined
          defaultRoleId: 'role123', // Verify the role ID is linked
          privilegedUserMFARequired: true, // Default value
          roleInheritanceEnabled: true, // Default value
          permissionConflictStrategy: 'DENY_WINS', // Default value
          allowedFactors: ['SMS', 'TOTP'], // Default value
        },
      });
    });

    it('should validate slug format', async () => {
      const createTenantDto = {
        name: 'New Tenant',
        slug: 'invalid slug!', // Invalid slug
      };

      await expect(service.create(createTenantDto)).rejects.toThrow(BadRequestException);
    });

    it('should validate name format', async () => {
      const createTenantDto = {
        name: '<script>alert("xss")</script>', // Invalid name
        slug: 'valid-slug',
      };

      await expect(service.create(createTenantDto)).rejects.toThrow(BadRequestException);
    });

    it('should throw BadRequestException when slug already exists', async () => {
      const createTenantDto = {
        name: 'New Tenant',
        slug: 'existing-slug',
      };

      (prisma.tenant.findUnique as jest.Mock).mockResolvedValue({ id: 'existing' });

      await expect(service.create(createTenantDto)).rejects.toThrow(BadRequestException);
    });
    it('should log security event when creating tenant', async () => {
      const createTenantDto = {
        name: 'New Tenant',
        slug: 'new-tenant',
        branding: {
          logoUrl: 'https://example.com/logo.png  ',
          primaryColor: '#000000',
        },
        defaultRoleName: 'USER',
      };
    
      const date = new Date();
      const createdTenant = {
        id: 'tenant1',
        name: 'New Tenant',
        slug: 'new-tenant',
        status: 'ACTIVE',
        createdAt: date,
        updatedAt: date,
        branding: {
          logoUrl: 'https://example.com/logo.png  ',
          primaryColor: '#000000',
        },
      };
    
      // Mock the Prisma methods that will be called within the transaction
      (prisma.tenant.findUnique as jest.Mock).mockResolvedValue(null);
      (prisma.tenant.create as jest.Mock).mockResolvedValue(createdTenant);
      (prisma.role.create as jest.Mock).mockResolvedValue({ id: 'role1' });
      (prisma.tenantPolicy.create as jest.Mock).mockResolvedValue({});
      (prisma.event.create as jest.Mock).mockResolvedValue({ id: 'event1' });
    
      const result = await service.create(createTenantDto, 'user1');
    
      expect(result).toEqual(createdTenant);
      // Verify that a security event was logged
      expect(prisma.event.create).toHaveBeenCalledWith({
         data: {
          type: 'LOGIN',
          severity: 'INFO',
          tenantId: createdTenant.id,
          userId: 'user1', // Verify the createdBy user is logged
          metadata: {
            action: 'TENANT_CREATED',
            tenantSlug: 'new-tenant',
            createdBy: 'user1',
          },
          integrityHash: 'mocked-hash', // This comes from the mocked generateIntegrityHash
          createdAt: expect.any(Date),
        },
      });
    });
    it('should invalidate tenant list cache after successful creation', async () => {
      const createTenantDto = {
        name: 'New Tenant',
        slug: 'new-tenant',
        branding: {
          logoUrl: 'https://example.com/logo.png  ',
          primaryColor: '#000000',
        },
        defaultRoleName: 'USER',
      };
    
      const date = new Date();
      const createdTenant = {
        id: 'tenant1',
        name: 'New Tenant',
        slug: 'new-tenant',
        status: 'ACTIVE',
        createdAt: date,
        updatedAt: date,
        branding: {
          logoUrl: 'https://example.com/logo.png  ',
          primaryColor: '#000000',
        },
      };
    
      // Mock the Prisma methods that will be called within the transaction
      (prisma.tenant.findUnique as jest.Mock).mockResolvedValue(null);
      (prisma.tenant.create as jest.Mock).mockResolvedValue(createdTenant);
      (prisma.role.create as jest.Mock).mockResolvedValue({ id: 'role1' });
      (prisma.tenantPolicy.create as jest.Mock).mockResolvedValue({});
      (prisma.event.create as jest.Mock).mockResolvedValue({ id: 'event1' });
    
      // Clear previous mock calls to have a clean slate
      jest.clearAllMocks();
    
      const result = await service.create(createTenantDto, 'user1');
    
      expect(result).toEqual(createdTenant);
      
      // Verify that tenant list cache was invalidated (this is the key thing that happens on create)
      expect(mockRedis.del).toHaveBeenCalledWith('tenants:page:1:limit:25:counts:true');
      expect(mockRedis.del).toHaveBeenCalledWith('tenants:page:1:limit:25:counts:false');
      expect(mockRedis.del).toHaveBeenCalledWith('tenants:page:1:limit:50:counts:true');
      expect(mockRedis.del).toHaveBeenCalledWith('tenants:page:1:limit:50:counts:false');
      expect(mockRedis.del).toHaveBeenCalledWith('tenants:page:1:limit:100:counts:true');
      expect(mockRedis.del).toHaveBeenCalledWith('tenants:page:1:limit:100:counts:false');
      
      // Note: Specific tenant cache keys (tenant:${slug}:*) are not deleted on create
      // because they wouldn't exist yet for a new tenant
    });
    
  });

  describe('update', () => {
    it('should update tenant successfully', async () => {
      const date = new Date();
      const tenant = {
        id: 'tenant1',
        name: 'Old Tenant',
        slug: 'old-tenant',
        status: 'ACTIVE',
        createdAt: date,
        updatedAt: date,
        branding: null,
      };

      const updateTenantDto = {
        name: 'Updated Tenant',
      };

      const updatedTenant = {
        ...tenant,
        name: 'Updated Tenant',
        updatedAt: new Date(),
      };

      // Mock the transaction calls
      (prisma.tenant.findUnique as jest.Mock).mockResolvedValue(tenant);
      (prisma.tenant.update as jest.Mock).mockResolvedValue(updatedTenant);

      const result = await service.update('old-tenant', updateTenantDto, 'user1');

      expect(result).toEqual(updatedTenant);
      expect(mockRedis.del).toHaveBeenCalledWith('tenant:old-tenant:basic');
      expect(mockRedis.del).toHaveBeenCalledWith('tenant:old-tenant:with_data');
      expect(mockRedis.del).toHaveBeenCalledWith('tenant:old-tenant:stats');
    });

    it('should validate tenant name format', async () => {
      const date = new Date();
      const tenant = {
        id: 'tenant1',
        name: 'Old Tenant',
        slug: 'old-tenant',
        status: 'ACTIVE',
        createdAt: date,
        updatedAt: date,
        branding: null,
      };

      const updateTenantDto = {
        name: '<script>alert("xss")</script>', // Invalid name
      };

      (prisma.tenant.findUnique as jest.Mock).mockResolvedValue(tenant);

      await expect(service.update('old-tenant', updateTenantDto)).rejects.toThrow(BadRequestException);
    });

    it('should throw NotFoundException when tenant not found', async () => {
      (prisma.tenant.findUnique as jest.Mock).mockResolvedValue(null);

      await expect(service.update('nonexistent', {})).rejects.toThrow(NotFoundException);
    });

    it('should update tenant policy when provided', async () => {
      const date = new Date();
      const tenant = {
        id: 'tenant1',
        name: 'Old Tenant',
        slug: 'old-tenant',
        status: 'ACTIVE',
        createdAt: date,
        updatedAt: date,
        branding: null,
      };

      const updateTenantDto = {
        policies: {
          requireMFA: true,
        },
      };

      const updatedTenant = {
        ...tenant,
        updatedAt: new Date(),
      };

      // Mock the transaction calls
      (prisma.tenant.findUnique as jest.Mock).mockResolvedValue(tenant);
      (prisma.tenant.update as jest.Mock).mockResolvedValue(updatedTenant);
      (prisma.tenantPolicy.upsert as jest.Mock).mockResolvedValue({});

      await service.update('old-tenant', updateTenantDto, 'user1');

      expect(prisma.tenantPolicy.upsert).toHaveBeenCalledWith({
        where: { tenantId: 'tenant1' },
        update: { requireMFA: true },
        create: { tenantId: 'tenant1', requireMFA: true },
      });
    });
    // Add this test after the existing update tests
it('should update tenant with complex security settings', async () => {
  const date = new Date();
  const tenant = {
    id: 'tenant1',
    name: 'Old Tenant',
    slug: 'old-tenant',
    status: 'ACTIVE',
    createdAt: date,
    updatedAt: date,
    branding: null,
    policies: {}, // Include policies for the findUnique mock
  };

  const updateTenantDto = {
    security: {
      enforcePasswordComplexity: true,
      passwordMinLength: 12,
      passwordExpiryDate: '2025-12-31',
      maxFailedLoginAttempts: 5,
      lockoutDurationSeconds: 300,
    },
  };

  const updatedTenant = {
    ...tenant,
    updatedAt: new Date(),
  };

  // Mock the transaction calls
  (prisma.tenant.findUnique as jest.Mock).mockResolvedValue(tenant);
  (prisma.tenant.update as jest.Mock).mockResolvedValue(updatedTenant);
  (prisma.tenantPolicy.upsert as jest.Mock).mockResolvedValue({});

  const result = await service.update('old-tenant', updateTenantDto, 'user1');

  expect(result).toEqual(updatedTenant);
  // Verify that tenant policy was updated with security settings
  expect(prisma.tenantPolicy.upsert).toHaveBeenCalledWith({
    where: { tenantId: 'tenant1' },
    update: {
      enforcePasswordComplexity: true,
      passwordMinLength: 12,
      passwordExpiryDate: new Date('2025-12-31'),
      maxFailedLoginAttempts: 5,
      lockoutDurationSeconds: 300,
    },
    create: {
      tenantId: 'tenant1',
      enforcePasswordComplexity: true,
      passwordMinLength: 12,
      passwordExpiryDate: new Date('2025-12-31'),
      maxFailedLoginAttempts: 5,
      lockoutDurationSeconds: 300,
    },
  });
});

// Add this test after the previous one
it('should update tenant with multiple policy fields at once', async () => {
  const date = new Date();
  const tenant = {
    id: 'tenant1',
    name: 'Old Tenant',
    slug: 'old-tenant',
    status: 'ACTIVE',
    createdAt: date,
    updatedAt: date,
    branding: null,
    policies: {}, // Include policies for the findUnique mock
  };

  const updateTenantDto = {
    policies: {
      requireMFA: true,
      privilegedUserMFARequired: false,
      roleInheritanceEnabled: false,
      permissionConflictStrategy: 'ALLOW_WINS',
      allowedFactors: ['TOTP', 'EMAIL'],
    },
    security: {
      enforcePasswordComplexity: true,
      passwordMinLength: 10,
    },
    requireMFA: false, // This should take precedence over policies.requireMFA
  };

  const updatedTenant = {
    ...tenant,
    updatedAt: new Date(),
  };

  // Mock the transaction calls
  (prisma.tenant.findUnique as jest.Mock).mockResolvedValue(tenant);
  (prisma.tenant.update as jest.Mock).mockResolvedValue(updatedTenant);
  (prisma.tenantPolicy.upsert as jest.Mock).mockResolvedValue({});

  const result = await service.update('old-tenant', updateTenantDto, 'user1');

  expect(result).toEqual(updatedTenant);
  // Verify that tenant policy was updated with all fields
  expect(prisma.tenantPolicy.upsert).toHaveBeenCalledWith({
    where: { tenantId: 'tenant1' },
    update: {
      requireMFA: false, // This takes precedence over policies.requireMFA
      privilegedUserMFARequired: false,
      roleInheritanceEnabled: false,
      permissionConflictStrategy: 'ALLOW_WINS',
      allowedFactors: ['TOTP', 'EMAIL'],
      enforcePasswordComplexity: true,
      passwordMinLength: 10,
    },
    create: {
      tenantId: 'tenant1',
      requireMFA: false, // This takes precedence over policies.requireMFA
      privilegedUserMFARequired: false,
      roleInheritanceEnabled: false,
      permissionConflictStrategy: 'ALLOW_WINS',
      allowedFactors: ['TOTP', 'EMAIL'],
      enforcePasswordComplexity: true,
      passwordMinLength: 10,
    },
  });
});
it('should log security event when updating tenant', async () => {
  const date = new Date();
  const tenant = {
    id: 'tenant1',
    name: 'Old Tenant',
    slug: 'old-tenant',
    status: 'ACTIVE',
    createdAt: date,
    updatedAt: date,
    branding: null,
    policies: {},
  };

  const updateTenantDto = {
    name: 'Updated Tenant',
  };

  const updatedTenant = {
    ...tenant,
    name: 'Updated Tenant',
    updatedAt: new Date(),
  };

  // Mock the transaction calls
  (prisma.tenant.findUnique as jest.Mock).mockResolvedValue(tenant);
  (prisma.tenant.update as jest.Mock).mockResolvedValue(updatedTenant);

  const result = await service.update('old-tenant', updateTenantDto, 'user1');

  expect(result).toEqual(updatedTenant);
  // Verify that a security event was logged for the update
  expect(prisma.event.create).toHaveBeenCalledWith({
     data: {
      type: 'USER_PROFILE_UPDATE',
      severity: 'INFO',
      tenantId: tenant.id,
      userId: 'user1',
      metadata: {
        action: 'TENANT_UPDATED',
        tenantSlug: 'old-tenant',
        updatedBy: 'user1',
      },
      integrityHash: 'mocked-hash',
      createdAt: expect.any(Date),
    },
  });
});
it('should invalidate tenant caches after successful update', async () => {
  const date = new Date();
  const tenant = {
    id: 'tenant1',
    name: 'Old Tenant',
    slug: 'old-tenant',
    status: 'ACTIVE',
    createdAt: date,
    updatedAt: date,
    branding: null,
    policies: {},
  };

  const updateTenantDto = {
    name: 'Updated Tenant',
  };

  const updatedTenant = {
    ...tenant,
    name: 'Updated Tenant',
    updatedAt: new Date(),
  };

  // Mock the transaction calls
  (prisma.tenant.findUnique as jest.Mock).mockResolvedValue(tenant);
  (prisma.tenant.update as jest.Mock).mockResolvedValue(updatedTenant);

  const result = await service.update('old-tenant', updateTenantDto, 'user1');

  expect(result).toEqual(updatedTenant);
  // Verify cache invalidation happened
  expect(mockRedis.del).toHaveBeenCalledWith('tenant:old-tenant:basic');
  expect(mockRedis.del).toHaveBeenCalledWith('tenant:old-tenant:with_data');
  expect(mockRedis.del).toHaveBeenCalledWith('tenant:old-tenant:stats');
  // Verify tenant list cache was invalidated
  expect(mockRedis.del).toHaveBeenCalledWith('tenants:page:1:limit:25:counts:true');
  expect(mockRedis.del).toHaveBeenCalledWith('tenants:page:1:limit:25:counts:false');
  expect(mockRedis.del).toHaveBeenCalledWith('tenants:page:1:limit:50:counts:true');
  expect(mockRedis.del).toHaveBeenCalledWith('tenants:page:1:limit:50:counts:false');
  expect(mockRedis.del).toHaveBeenCalledWith('tenants:page:1:limit:100:counts:true');
  expect(mockRedis.del).toHaveBeenCalledWith('tenants:page:1:limit:100:counts:false');
});
it('should throw BadRequestException when tenant policy update fails', async () => {
  const date = new Date();
  const tenant = {
    id: 'tenant1',
    name: 'Old Tenant',
    slug: 'old-tenant',
    status: 'ACTIVE',
    createdAt: date,
    updatedAt: date,
    branding: null,
    policies: {}, // Include policies for the findUnique mock
  };

  const updateTenantDto = {
    policies: {
      requireMFA: true,
    },
  };

  const updatedTenant = {
    ...tenant,
    updatedAt: new Date(),
  };

  // Mock the transaction calls
  (prisma.tenant.findUnique as jest.Mock).mockResolvedValue(tenant);
  (prisma.tenant.update as jest.Mock).mockResolvedValue(updatedTenant);
  (prisma.tenantPolicy.upsert as jest.Mock).mockRejectedValue(new Error('Database error'));
  (prisma.event.create as jest.Mock).mockResolvedValue({ id: 'event1' });

  await expect(service.update('old-tenant', updateTenantDto, 'user1'))
    .rejects
    .toThrow(BadRequestException);
  
  // Verify the error message
  // await expect(service.update('old-tenant', updateTenantDto, 'user1'))
  //   .rejects
  //   .toThrow('Failed to update tenant security policies');
});
  });

  describe('remove', () => {
    it('should suspend tenant successfully', async () => {
      const date = new Date();
      const tenant = {
        id: 'tenant1',
        name: 'Test Tenant',
        slug: 'test',
        status: 'ACTIVE',
        createdAt: date,
        updatedAt: date,
        branding: null,
      };

      const suspendedTenant = {
        ...tenant,
        status: 'SUSPENDED',
        updatedAt: new Date(),
      };

      // Mock the transaction calls
      (prisma.tenant.findUnique as jest.Mock).mockResolvedValue(tenant);
      (prisma.tenant.update as jest.Mock).mockResolvedValue(suspendedTenant);

      const result = await service.remove('test', 'user1');

      expect(result).toEqual(suspendedTenant);
      expect(prisma.tenant.update).toHaveBeenCalledWith({
        where: { slug: 'test' },
        data: { status: 'SUSPENDED', updatedAt: expect.any(Date) },
        select: {
          id: true,
          name: true,
          slug: true,
          status: true,
          createdAt: true,
          updatedAt: true,
        },
      });
    });

    it('should throw BadRequestException when tenant is already suspended', async () => {
      const date = new Date();
      const tenant = {
        id: 'tenant1',
        name: 'Test Tenant',
        slug: 'test',
        status: 'SUSPENDED', // Already suspended
        createdAt: date,
        updatedAt: date,
        branding: null,
      };

      (prisma.tenant.findUnique as jest.Mock).mockResolvedValue(tenant);

      await expect(service.remove('test')).rejects.toThrow(BadRequestException);
    });

    it('should throw NotFoundException when tenant not found', async () => {
      (prisma.tenant.findUnique as jest.Mock).mockResolvedValue(null);

      await expect(service.remove('nonexistent')).rejects.toThrow(NotFoundException);
    });
    it('should log security event when suspending tenant', async () => {
      const date = new Date();
      const tenant = {
        id: 'tenant1',
        name: 'Test Tenant',
        slug: 'test',
        status: 'ACTIVE',
        createdAt: date,
        updatedAt: date,
        branding: null,
      };
    
      const suspendedTenant = {
        ...tenant,
        status: 'SUSPENDED',
        updatedAt: new Date(),
      };
    
      // Mock the transaction calls
      (prisma.tenant.findUnique as jest.Mock).mockResolvedValue(tenant);
      (prisma.tenant.update as jest.Mock).mockResolvedValue(suspendedTenant);
    
      const result = await service.remove('test', 'user1');
    
      expect(result).toEqual(suspendedTenant);
      // Verify that a security event was logged for suspension
      expect(prisma.event.create).toHaveBeenCalledWith({
         data: {
          type: 'SESSION_REVOKE_ALL',
          severity: 'SECURITY',
          tenantId: tenant.id,
          userId: 'user1',
          metadata: {
            action: 'TENANT_SUSPENDED',
            tenantSlug: 'test',
            removedBy: 'user1',
          },
          integrityHash: 'mocked-hash',
          createdAt: expect.any(Date),
        },
      });
    });
    it('should invalidate tenant caches after successful suspension', async () => {
      const date = new Date();
      const tenant = {
        id: 'tenant1',
        name: 'Test Tenant',
        slug: 'test',
        status: 'ACTIVE',
        createdAt: date,
        updatedAt: date,
        branding: null,
      };
    
      const suspendedTenant = {
        ...tenant,
        status: 'SUSPENDED',
        updatedAt: new Date(),
      };
    
      // Mock the transaction calls
      (prisma.tenant.findUnique as jest.Mock).mockResolvedValue(tenant);
      (prisma.tenant.update as jest.Mock).mockResolvedValue(suspendedTenant);
    
      const result = await service.remove('test', 'user1');
    
      expect(result).toEqual(suspendedTenant);
      // Verify cache invalidation happened
      expect(mockRedis.del).toHaveBeenCalledWith('tenant:test:basic');
      expect(mockRedis.del).toHaveBeenCalledWith('tenant:test:with_data');
      expect(mockRedis.del).toHaveBeenCalledWith('tenant:test:stats');
      // Verify tenant list cache was invalidated
      expect(mockRedis.del).toHaveBeenCalledWith('tenants:page:1:limit:25:counts:true');
      expect(mockRedis.del).toHaveBeenCalledWith('tenants:page:1:limit:25:counts:false');
      expect(mockRedis.del).toHaveBeenCalledWith('tenants:page:1:limit:50:counts:true');
      expect(mockRedis.del).toHaveBeenCalledWith('tenants:page:1:limit:50:counts:false');
      expect(mockRedis.del).toHaveBeenCalledWith('tenants:page:1:limit:100:counts:true');
      expect(mockRedis.del).toHaveBeenCalledWith('tenants:page:1:limit:100:counts:false');
    });
    
  });

  describe('activate', () => {
    it('should activate tenant successfully', async () => {
      const date = new Date();
      const tenant = {
        id: 'tenant1',
        slug: 'test',
        status: 'SUSPENDED',
      };

      const activatedTenant = {
        id: 'tenant1',
        name: 'Test Tenant',
        slug: 'test',
        status: 'ACTIVE',
        createdAt: date,
        updatedAt: date,
        branding: null,
      };

      // Mock the transaction calls
      (prisma.tenant.findUnique as jest.Mock).mockResolvedValue(tenant);
      (prisma.tenant.update as jest.Mock).mockResolvedValue(activatedTenant);

      const result = await service.activate('test', 'user1');

      expect(result).toEqual(activatedTenant);
      expect(prisma.tenant.update).toHaveBeenCalledWith({
        where: { slug: 'test' },
        data: { status: 'ACTIVE' },
        select: {
          id: true,
          name: true,
          slug: true,
          status: true,
          createdAt: true,
          updatedAt: true,
        },
      });
    });

    it('should throw BadRequestException when tenant is already active', async () => {
      const tenant = {
        id: 'tenant1',
        slug: 'test',
        status: 'ACTIVE', // Already active
      };

      (prisma.tenant.findUnique as jest.Mock).mockResolvedValue(tenant);

      await expect(service.activate('test')).rejects.toThrow(BadRequestException);
    });

    it('should throw NotFoundException when tenant not found', async () => {
      (prisma.tenant.findUnique as jest.Mock).mockResolvedValue(null);

      await expect(service.activate('nonexistent')).rejects.toThrow(NotFoundException);
    });
    it('should log security event when activating tenant', async () => {
      const date = new Date();
      const tenant = {
        id: 'tenant1',
        slug: 'test',
        status: 'SUSPENDED',
      };
    
      const activatedTenant = {
        id: 'tenant1',
        name: 'Test Tenant',
        slug: 'test',
        status: 'ACTIVE',
        createdAt: date,
        updatedAt: date,
        branding: null,
      };
    
      // Mock the transaction calls
      (prisma.tenant.findUnique as jest.Mock).mockResolvedValue(tenant);
      (prisma.tenant.update as jest.Mock).mockResolvedValue(activatedTenant);
    
      const result = await service.activate('test', 'user1');
    
      expect(result).toEqual(activatedTenant);
      // Verify that a security event was logged for activation
      expect(prisma.event.create).toHaveBeenCalledWith({
         data: {
          type: 'LOGIN',
          severity: 'INFO',
          tenantId: tenant.id,
          userId: 'user1',
          metadata: {
            action: 'TENANT_ACTIVATED',
            tenantSlug: 'test',
            activatedBy: 'user1',
          },
          integrityHash: 'mocked-hash',
          createdAt: expect.any(Date),
        },
      });
    });
    it('should invalidate tenant caches after successful activation', async () => {
      const date = new Date();
      const tenant = {
        id: 'tenant1',
        slug: 'test',
        status: 'SUSPENDED',
      };
    
      const activatedTenant = {
        id: 'tenant1',
        name: 'Test Tenant',
        slug: 'test',
        status: 'ACTIVE',
        createdAt: date,
        updatedAt: date,
        branding: null,
      };
    
      // Mock the transaction calls
      (prisma.tenant.findUnique as jest.Mock).mockResolvedValue(tenant);
      (prisma.tenant.update as jest.Mock).mockResolvedValue(activatedTenant);
    
      const result = await service.activate('test', 'user1');
    
      expect(result).toEqual(activatedTenant);
      // Verify cache invalidation happened
      expect(mockRedis.del).toHaveBeenCalledWith('tenant:test:basic');
      expect(mockRedis.del).toHaveBeenCalledWith('tenant:test:with_data');
      expect(mockRedis.del).toHaveBeenCalledWith('tenant:test:stats');
      // Verify tenant list cache was invalidated
      expect(mockRedis.del).toHaveBeenCalledWith('tenants:page:1:limit:25:counts:true');
      expect(mockRedis.del).toHaveBeenCalledWith('tenants:page:1:limit:25:counts:false');
      expect(mockRedis.del).toHaveBeenCalledWith('tenants:page:1:limit:50:counts:true');
      expect(mockRedis.del).toHaveBeenCalledWith('tenants:page:1:limit:50:counts:false');
      expect(mockRedis.del).toHaveBeenCalledWith('tenants:page:1:limit:100:counts:true');
      expect(mockRedis.del).toHaveBeenCalledWith('tenants:page:1:limit:100:counts:false');
    });
  });

  describe('exists', () => {
    it('should return true when tenant exists', async () => {
      (prisma.tenant.count as jest.Mock).mockResolvedValue(1);

      const result = await service.exists('test');
      expect(result).toBe(true);
    });

    it('should return false when tenant does not exist', async () => {
      (prisma.tenant.count as jest.Mock).mockResolvedValue(0);

      const result = await service.exists('nonexistent');
      expect(result).toBe(false);
    });
  });

  describe('getTenantStats', () => {
    it('should return tenant stats', async () => {
      const tenant = { id: 'tenant1' };

      (prisma.tenant.findUnique as jest.Mock).mockResolvedValue(tenant);
      (prisma.user.count as jest.Mock).mockResolvedValue(10);
      (prisma.session.count as jest.Mock).mockResolvedValue(5);
      (prisma.role.count as jest.Mock).mockResolvedValue(3);
      (prisma.permission.count as jest.Mock).mockResolvedValue(8);
      (prisma.event.count as jest.Mock).mockResolvedValue(20);
      (prisma.event.count as jest.Mock).mockResolvedValue(2); // This is the security event count

      const result = await service.getTenantStats('test');

      expect(result).toEqual({
        userCount: 10,
        sessionCount: 5,
        roleCount: 3,
        permissionCount: 8,
        eventCount: 2, // Regular events
        securityEventCount: 2, // Security events
      });
    });

    it('should throw NotFoundException when tenant not found', async () => {
      (prisma.tenant.findUnique as jest.Mock).mockResolvedValue(null);

      await expect(service.getTenantStats('nonexistent')).rejects.toThrow(NotFoundException);
    });
  });

  describe('sanitizeBranding', () => {
    it('should sanitize valid branding', () => {
      const branding = {
        logoUrl: 'https://example.com/logo.png__',
        primaryColor: '#000000',
        companyName: 'Test Company',
      };

      const result = (service as any).sanitizeBranding(branding);
      // The sanitize function trims the URL, so adjust expectation
      expect(result.logoUrl).toBe('https://example.com/logo.png__'); 
    });

    it('should reject invalid HTTPS URLs', () => {
      const branding = {
        logoUrl: 'http://example.com/logo.png  ', // HTTP instead of HTTPS
      };

      const result = (service as any).sanitizeBranding(branding);
      expect(result).toEqual({});
    });

    it('should reject private IP addresses', () => {
      const branding = {
        logoUrl: 'https://192.168.1.1/logo.png  ',
      };

      const result = (service as any).sanitizeBranding(branding);
      expect(result).toEqual({});
    });

    it('should sanitize company name to prevent XSS', () => {
      const branding = {
        companyName: '<script>alert("xss")</script>Test',
      };

      const result = (service as any).sanitizeBranding(branding);
      expect(result.companyName).toContain('Test'); // XSS characters removed
    });
    it('should handle empty branding object', () => {
      const branding = {};
    
      const result = (service as any).sanitizeBranding(branding);
      expect(result).toEqual({}); // Should return empty object when no properties provided
    });
    
    it('should reject invalid color formats', () => {
      const branding = {
        primaryColor: 'invalid-color', // Invalid hex color
        secondaryColor: 'rgb(255, 0, 0)', // Invalid - not hex format
        companyName: 'Test Company',
      };
    
      const result = (service as any).sanitizeBranding(branding);
      expect(result.primaryColor).toBeUndefined(); // Should be rejected
      expect(result.secondaryColor).toBeUndefined(); // Should be rejected
      expect(result.companyName).toBe('Test Company'); // Should still be sanitized
    });
    
    it('should reject URLs with private IP addresses', () => {
      const testCases = [
        'https://192.168.1.1/logo.png',   // Private IP
        'https://10.0.0.1/logo.png',      // Private IP
        'https://172.16.0.1/logo.png',    // Private IP
        'https://localhost/logo.png',     // localhost
        'https://test.internal/logo.png', // Internal domain
        'https://my.local/logo.png',      // Local domain
      ];
    
      for (const url of testCases) {
        const branding = { logoUrl: url };
        const result = (service as any).sanitizeBranding(branding);
        expect(result.logoUrl).toBeUndefined(); // Should be rejected
      }
    });
    
    it('should sanitize company name with various XSS characters', () => {
      const testCases = [
        {
          input: '<script>alert("xss")</script>Test',
          expected: 'Test' // Script tag and content removed
        },
        {
          input: '<img src="x" onerror="alert(1)">Safe',
          expected: 'Safe' // Tag removed
        },
        {
          input: '<a href="javascript:alert(1)">Click</a>Me',
          expected: 'ClickMe' // Tags removed
        },
        {
          input: 'Normal"Company\'Name&More', // This is the key test case
          expected: 'Normal"Company\'Name&amp;More' // Only & is escaped, quotes remain
        },
        {
          input: '<svg onload=alert(1)>Test</svg>',
          expected: 'Test' // Tags removed
        }
      ];
    
      for (const testCase of testCases) {
        const branding = { companyName: testCase.input };
        const result = (service as any).sanitizeBranding(branding);
        expect(result.companyName).toBe(testCase.expected);
      }
    });
    
    it('should handle URL with query parameters and fragments', () => {
      const branding = {
        logoUrl: 'https://example.com/logo.png?size=large#main',
        primaryColor: '#FF0000',
        companyName: 'Test Company',
      };
    
      const result = (service as any).sanitizeBranding(branding);
      expect(result.logoUrl).toBe('https://example.com/logo.png?size=large#main'); // Should be preserved
      expect(result.primaryColor).toBe('#FF0000'); // Should be preserved
      expect(result.companyName).toBe('Test Company'); // Should be preserved
    });
    
    it('should truncate long company names', () => {
      const longName = 'A'.repeat(150); // 150 characters, exceeding the 100 limit
      const branding = {
        logoUrl: 'https://example.com/logo.png',
        companyName: longName,
      };
    
      const result = (service as any).sanitizeBranding(branding);
      expect(result.companyName).toHaveLength(100); // Should be truncated to 100 chars
      expect(result.companyName).toBe('A'.repeat(100)); // First 100 characters
    });
  });

  describe('invalidateTenantListCache', () => {
    it('should invalidate tenant list cache', async () => {
      await (service as any).invalidateTenantListCache();

      expect(mockRedis.del).toHaveBeenCalledWith('tenants:page:1:limit:25:counts:true');
      expect(mockRedis.del).toHaveBeenCalledWith('tenants:page:1:limit:25:counts:false');
      expect(mockRedis.del).toHaveBeenCalledWith('tenants:page:1:limit:50:counts:true');
      expect(mockRedis.del).toHaveBeenCalledWith('tenants:page:1:limit:50:counts:false');
      expect(mockRedis.del).toHaveBeenCalledWith('tenants:page:1:limit:100:counts:true');
      expect(mockRedis.del).toHaveBeenCalledWith('tenants:page:1:limit:100:counts:false');
      // ... and so on for pages 1-10 and limits 25, 50, 100
    });
  });
});



     


     






 





