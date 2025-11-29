// src/tenants/__tests__/tenants.lifecycle.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import request from 'supertest'; // Using supertest for HTTP-like lifecycle simulation
import { AppModule } from '../../app.module'; // Assuming AppModule imports TenantsModule
import { PrismaService } from '../../prisma/prisma.service';
import { EventLogService } from '../../events/event.service';
import { TenantsService } from '../tenants.service';
import { AllowedFactor, CreateTenantDto, PermissionConflictStrategy } from '../dto/create-tenant.dto';
import { UpdateTenantDto } from '../dto/update-tenant.dto';
import { TenantStatusEnum } from '../dto/create-tenant.dto';
import { mockDeep, DeepMockProxy } from 'jest-mock-extended'; // Or your chosen mocking library
import { Redis } from 'ioredis';
import { BadRequestException, ForbiddenException, NotFoundException } from '@nestjs/common';
import { JwtModule, JwtService } from '@nestjs/jwt';
import cookieParser from 'cookie-parser';
// Define types for request object structure used in tests
// interface MockUser { ... }
// interface MockTenant { ... }
// interface MockRequest { ... }
// Mock data
const mockSuperAdminUser = {
  id: 'user-id-super-admin',
  sub: 'user-super-admin',
  tenantId: 'system-tenant',
};
const mockSuperAdminTenant = {
  id: 'system-tenant',
  slug: 'system-tenant',
  name: 'System Tenant',
  status: 'ACTIVE',
};
const mockSuperAdminRequest = {
  user: mockSuperAdminUser,
  tenant: mockSuperAdminTenant,
  ip: '192.168.1.100',
  headers: { 'user-agent': 'test-agent-super-admin' },
  cookies: { latch_session: 'session-id-super-admin', latch_csrf: 'csrf-token-super-admin' },
};
const mockAdminUser = {
  id: 'user-id-admin',
  sub: 'user-admin',
  tenantId: 'tenant-acme-corp',
};
const mockAdminTenant = {
  id: 'tenant-acme-corp',
  slug: 'acme-corp',
  name: 'Acme Corp',
  status: 'ACTIVE',
};
const mockAdminRequest = {
  user: mockAdminUser,
  tenant: mockAdminTenant,
  ip: '192.168.1.101',
  headers: { 'user-agent': 'test-agent-admin' },
  cookies: { latch_session: 'session-id-admin', latch_csrf: 'csrf-token-admin' },
};
const validCreateDto: CreateTenantDto = {
  name: 'Lifecycle Test Tenant',
  slug: 'lifecycle-test-tenant',
  status: TenantStatusEnum.ACTIVE,
  branding: {
    logoUrl: 'https://secure.example.com/logo.png',
    primaryColor: '#007bff',
    companyName: 'Lifecycle Test Co',
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
  name: 'Updated Lifecycle Tenant Name',
  branding: {
    primaryColor: '#dc3545', // Red
  },
  policies: {
    requireMFA: false, // Turn off MFA
  },
  security: {
    enforcePasswordComplexity: false, // Relax security setting
  },
};
// Define expected tenant object shapes after service calls
const expectedCreatedTenant = {
    name: 'Lifecycle Test Tenant',
    slug: 'lifecycle-test-tenant',
    status: 'ACTIVE',
    createdAt: new Date(),
    updatedAt: new Date(),
    branding: {
      logoUrl: 'https://secure.example.com/logo.png',
      primaryColor: '#007bff',
      companyName: 'Lifecycle Test Co',
    },
  };
const expectedUpdatedTenant = {
  ...expectedCreatedTenant,
  name: 'Updated Lifecycle Tenant Name',
  branding: {
    ...expectedCreatedTenant.branding,
    primaryColor: '#dc3545', // Updated color
  },
  updatedAt: new Date(), // Should be updated
};
const expectedSuspendedTenant = {
  ...expectedUpdatedTenant,
  status: 'SUSPENDED', // Status changed
  updatedAt: new Date(), // Should be updated
};
const expectedActivatedTenant = {
  ...expectedSuspendedTenant,
  status: 'ACTIVE', // Status changed back
  updatedAt: new Date(), // Should be updated
};

// --- CSRF TOKEN CONSISTENCY HELPER ---
const csrfTokens = {
  super1: 'csrf-token-super-admin',
  super2: 'csrf-token-super-admin-2',
  super3: 'csrf-token-super-admin-3',
  super4: 'csrf-token-super-admin-4',
  admin: 'csrf-token-admin',
  member: 'csrf-token-member',
};
// --- END CSRF TOKEN CONSISTENCY HELPER ---

describe('TenantsController Lifecycle Integration Tests', () => {
    let app: INestApplication;
    let prismaService: DeepMockProxy<PrismaService>;
    let eventLogService: DeepMockProxy<EventLogService>;
    let tenantsService: DeepMockProxy<TenantsService>; // <--- Use DeepMockProxy for the service
    let jwtService: JwtService; // <--- Add JwtService instance
    let redisService: jest.Mocked<Redis>;
    const mockPrisma = mockDeep<PrismaService>();
    const mockEventLog = mockDeep<EventLogService>();
    // let prisma: PrismaService;
    let moduleFixture: TestingModule;
    const mockRedis = {
      get: jest.fn(),
      setex: jest.fn(),
      del: jest.fn(),
      quit: jest.fn().mockResolvedValue('OK'), 
      disconnect: jest.fn(),
    } as unknown as jest.Mocked<Redis>;
    // Create a DeepMockProxy for the service itself
    const mockTenantsService = mockDeep<TenantsService>();
    beforeAll(async () => {
      const moduleRef: TestingModule = await Test.createTestingModule({
        imports: [
          AppModule,
          // Import JwtModule to make JwtService available
          JwtModule.register({
            secret: process.env.JWT_SECRET ?? 'dev_jwt_secret_change_me', // Use same secret as strategy
            signOptions: { expiresIn: '1h' }, // Optional: set default expiry if needed
          }),
        ],
      })
      .overrideProvider(PrismaService) // Override PrismaService with mock
      .useValue({
        ...mockPrisma,
        // Explicitly define the userRole model mock
        userRole: {
          findMany: jest.fn(),
          // Add other methods if used by your guards/services
          create: jest.fn(),
          deleteMany: jest.fn(),
        },
        // ADD these models that the services use during initialization
        event: {
          findMany: jest.fn().mockResolvedValue([]), // For IPReputationService, BehavioralAnalysisService, and warmupCache
          create: jest.fn(),
          findUnique: jest.fn(),
          findFirst: jest.fn(),
          count: jest.fn(),
        },
        tenantRateLimitProfile: {
          findFirst: jest.fn().mockResolvedValue(null), // For RateLimitingService
          findMany: jest.fn().mockResolvedValue([]), // For RateLimitingService warmup
          create: jest.fn(),
          update: jest.fn(),
        },
        session: {
          findMany: jest.fn().mockResolvedValue([]), // For DeviceFingerprintingService
          findUnique: jest.fn(),
          findFirst: jest.fn(),
          create: jest.fn(),
          update: jest.fn(),
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
        // ADD THESE MODELS that IPReputationService uses
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
            userRole: {
              findMany: jest.fn(),
              create: jest.fn(),
              deleteMany: jest.fn(),
            },
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
            tenant: {
              findUnique: jest.fn(),
              // ... other tenant methods if used by analytics
           },
            // ADD THESE models to transaction object for IPReputationService
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
      .overrideProvider(EventLogService) // Optionally override EventLogService
      .useValue(mockEventLog)
      .overrideProvider('REDIS') // Override Redis
      .useValue(mockRedis)
      .overrideProvider(TenantsService) // <--- OVERRIDE TenantsService with mock
      .useValue(mockTenantsService) // <--- Use the mockTenantsService instance
      // Do NOT override JwtService itself, let JwtModule provide it
      .compile();
      app = moduleRef.createNestApplication();
      // Apply cookie parsing middleware - ESSENTIAL for CSRF guard
      app.use(cookieParser()); // <--- ADD THIS LINE
      await app.init();
      // Retrieve instances from the compiled module reference
      // tenantsService is now the mockTenantsService
      tenantsService = moduleRef.get(TenantsService) as DeepMockProxy<TenantsService>;
      prismaService = moduleRef.get(PrismaService) as DeepMockProxy<PrismaService>;
      eventLogService = moduleRef.get(EventLogService) as DeepMockProxy<EventLogService>;
      jwtService = moduleRef.get<JwtService>(JwtService); // <--- Now this should work
      redisService = moduleRef.get('REDIS') as jest.Mocked<Redis>;
    });

    beforeEach(() => {
      jest.clearAllMocks();
      // --- CRITICAL: Mock Prisma calls needed by JwtStrategy ---
      // The JwtStrategy calls prisma.session.findUnique({ where: { id: payload.sessionId }, include: { user: true } })
      // It expects the session to exist, not be revoked/expired, and the user to be included.
      (prismaService.session.findUnique as jest.Mock).mockImplementation(({ where, include }) => {
        const sessionId = where?.id;
        if (sessionId === 'session-id-super-admin') {
          // Return a session object for the super admin token, including the user
          return Promise.resolve({
            id: 'session-id-super-admin',
            csrfToken: csrfTokens.super1, // <--- FIXED: Now matches cookie/header value
            userId: mockSuperAdminUser.id, // Links session to user
            tenantId: mockSuperAdminUser.tenantId, // Links session to tenant
            revoked: false, // Must be false
            expiresAt: new Date(Date.now() + 3600000), // Must be in the future
            user: mockSuperAdminUser, // Crucially, includes the user object
            // Add other session fields if the strategy accesses them
          });
        } else if (sessionId === 'session-id-admin') {
           // Return a session object for the admin token, including the user
           return Promise.resolve({
              id: 'session-id-admin',
              csrfToken: csrfTokens.admin, // <--- FIXED: Now matches cookie/header value
              userId: mockAdminUser.id, // Links session to user
              tenantId: mockAdminUser.tenantId, // Links session to tenant
              revoked: false, // Must be false
              expiresAt: new Date(Date.now() + 3600000), // Must be in the future
              user: mockAdminUser, // Crucially, includes the user object
              // Add other session fields if the strategy accesses them
            });
        } else if (sessionId === 'session-id-super-admin-2') {
            // Return a session object for the super admin token (deactivate step), including the user
            return Promise.resolve({
              id: 'session-id-super-admin-2',
              csrfToken: csrfTokens.super2, // <--- FIXED: Now matches cookie/header value
              userId: mockSuperAdminUser.id,
              tenantId: mockSuperAdminUser.tenantId,
              revoked: false,
              expiresAt: new Date(Date.now() + 3600000),
              user: mockSuperAdminUser,
            });
        } else if (sessionId === 'session-id-super-admin-3') {
             // Return a session object for the super admin token (activate step), including the user
             return Promise.resolve({
              id: 'session-id-super-admin-3',
              csrfToken: csrfTokens.super3, // <--- FIXED: Now matches cookie/header value
              userId: mockSuperAdminUser.id,
              tenantId: mockSuperAdminUser.tenantId,
              revoked: false,
              expiresAt: new Date(Date.now() + 3600000),
              user: mockSuperAdminUser,
            });
        } else if (sessionId === 'session-id-member') {
             // Return a session object for the member user token (read step), including the user
             return Promise.resolve({
              id: 'session-id-member',
              csrfToken: csrfTokens.member, // <--- FIXED: Now matches cookie/header value
              userId: 'user-member-id',
              tenantId: 'generated-tenant-id-lifecycle', // Use the ID from the created tenant
              revoked: false,
              expiresAt: new Date(Date.now() + 3600000),
              user: { id: 'user-member-id', sub: 'user-member', tenantId: 'generated-tenant-id-lifecycle' }, // Basic user object
            });
        }
        // Add more conditions for other session IDs if needed (e.g., for member token later)
        // } else if (sessionId === 'session-id-member') { ... }
        return Promise.resolve(null); // Return null if session ID not found
      });

      // --- CRITICAL: Mock Prisma calls needed by RolesGuard (BEFORE specific steps) ---
      // Provide a default mock that can be overridden by step-specific mocks.
      // The RolesGuard calls prisma.userRole.findMany({ where: { userId: ..., role: { tenantId: ... } } })
      (prismaService.userRole.findMany as jest.Mock).mockImplementation(({ where }) => {
          // Log the incoming arguments for debugging
          console.log('[TEST - beforeEach] userRole.findMany called with where:', where);

          // Check for SUPER_ADMIN on system tenant (nested role.tenantId structure, matching RolesGuard)
          if (where?.userId === mockSuperAdminUser.id && where?.role?.tenantId === mockSuperAdminUser.tenantId) {
            console.log('[TEST - beforeEach] Returning SUPER_ADMIN role for super admin.');
            return Promise.resolve([{ role: { name: 'SUPER_ADMIN', isSystem: true, privileges: ['cross_tenant_access'] } }]); // Add privilege for TenantGuard
          }
          // Check for ADMIN on a specific tenant (nested role.tenantId structure)
          if (where?.userId === mockAdminUser.id && where?.role?.tenantId === mockAdminUser.tenantId) {
            console.log('[TEST - beforeEach] Returning ADMIN role for admin user.');
            return Promise.resolve([{ role: { name: 'ADMIN', isSystem: false, privileges: [] } }]);
          }
          // Check for USER on a specific tenant (nested role.tenantId structure)
          if (where?.userId === 'user-member-id' && where?.role?.tenantId === 'generated-tenant-id-lifecycle') {
            console.log('[TEST - beforeEach] Returning USER role for member user.');
            return Promise.resolve([{ role: { name: 'USER', isSystem: false, privileges: [] } }]);
          }

          // For any other user/tenant combination, return empty array
          console.log('[TEST - beforeEach] Returning empty roles array for other user/tenant.');
          return Promise.resolve([]);
      });

      // --- Potentially Needed: Mock Prisma calls for TenantGuard ---
      // The TenantGuard calls prisma.tenant.findUnique. A default mock might be useful here,
      // but again, specific test steps will likely override it.
      // Example default (will be overridden by step-specific mocks):
      // (prismaService.tenant.findUnique as jest.Mock).mockResolvedValue(null); // Or a default structure
    });
    afterAll(async () => {
      // 1. Shut down the NestJS application instance (stops HTTP server)
      if (app) {
        await app.close();
      }
      
      // 2. Explicitly disconnect Prisma client
      if (prismaService && prismaService.$disconnect) {
        await prismaService.$disconnect();
      }
  
      // 3. Check for and disconnect the Redis client if it's initialized
      // (You might need to get the Redis instance from the module context if it's used)
      // try {
      //     const redisService = moduleFixture.get<Redis>('IOREDIS_CLIENT'); // Adjust token if needed
      //     if (redisService && typeof redisService.quit === 'function') {
      //         await redisService.quit(); // Use .quit() to ensure connection closes
      //     }
      // } catch (e) {
      //     // Handle cases where Redis might not be provided in this specific test
      // }
      
      // If you use 'jest-mock-extended' (as imported), reset all mocks:
      jest.clearAllMocks();
    });
  describe('Full Tenant Lifecycle: Create -> Update -> Deactivate -> Activate -> Read', () => {
    it('should successfully execute the full tenant lifecycle via HTTP requests', async () => {
      // --- Step 1: Create Tenant ---
      // Mock RolesGuard (SUPER_ADMIN check for create) using mockImplementation
      // This mock handles calls specifically for the super admin user during the CREATE request.
      // It must be set *after* beforeEach clears mocks but *before* the request.
      (prismaService.userRole.findMany as jest.Mock).mockImplementation(({ where }) => {
          // Log the incoming arguments for debugging
          console.log('[TEST - Create Step] userRole.findMany called with where:', where);
          // Check the correct structure: userId at top level, tenantId nested within the role object
          if (where?.userId === mockSuperAdminUser.id && where?.role?.tenantId === mockSuperAdminUser.tenantId) { // Use nested role.tenantId
            console.log('[TEST - Create Step] Returning SUPER_ADMIN role for CREATE request.');
            return Promise.resolve([{ role: { name: 'SUPER_ADMIN', isSystem: true, privileges: ['cross_tenant_access'] } }]); // Add privilege for TenantGuard
          }
          // For any other user/tenant combination, return empty array
          console.log('[TEST - Create Step] Returning empty roles array for other user/tenant.');
          return Promise.resolve([]);
        });
      // Mock the session for the JWT strategy and CSRF guard using mockImplementation
      (prismaService.session.findUnique as jest.Mock).mockImplementation(({ where, include }) => {
        const sessionId = where?.id;
        if (sessionId === 'session-id-super-admin') {
          return Promise.resolve({
            id: 'session-id-super-admin',
            csrfToken: csrfTokens.super1, // <--- FIXED: Now matches cookie/header value
            userId: mockSuperAdminUser.id,
            tenantId: mockSuperAdminUser.tenantId,
            revoked: false,
            expiresAt: new Date(Date.now() + 3600000),
            user: mockSuperAdminUser,
          });
        }
        return Promise.resolve(null);
      });
      // Mock the SERVICE call for create - THIS IS THE KEY CHANGE
      const createdTenant = { 
        ...expectedCreatedTenant, 
        id: 'generated-tenant-id-lifecycle', // Use an actual string ID
        createdAt: new Date(),
        updatedAt: new Date()
      };
      (tenantsService.create as jest.Mock).mockResolvedValue(createdTenant);
      // Sign a JWT token for the super admin user
      const validJwtTokenSuperAdmin = jwtService.sign({
        sub: mockSuperAdminUser.id, // sub maps to user ID
        id: mockSuperAdminUser.id,  // Include id if strategy or other parts expect it
        tenantId: mockSuperAdminUser.tenantId,
        sessionId: 'session-id-super-admin', // Crucial: This sessionId must match the mock above
        // Add other expected claims like mfa, iat, exp if necessary
        mfa: false,
      }, { secret: process.env.JWT_SECRET ?? 'dev_jwt_secret_change_me' }); // Use same secret as strategy

      const createResponse = await request(app.getHttpServer())
  .post('/v1/tenants')
  .set('Authorization', `Bearer ${validJwtTokenSuperAdmin}`) // <--- Use the generated token
  .set('X-CSRF-Token', csrfTokens.super1) // <--- FIXED: Now matches cookie/DB value
  .set('Cookie', ['latch_session=session-id-super-admin', 'latch_csrf=csrf-token-super-admin'])
  .send(validCreateDto)
  .expect(201);

      // Use objectContaining to handle date serialization
      expect(createResponse.body).toEqual(
        expect.objectContaining({
          id: createdTenant.id,
          name: createdTenant.name,
          slug: createdTenant.slug,
          status: createdTenant.status,
          branding: createdTenant.branding,
          createdAt: expect.any(String), // Dates become strings in JSON response
          updatedAt: expect.any(String),
        })
      );

      // Verify audit logs for creation (optional, based on controller implementation)
      expect(eventLogService.logEvent).toHaveBeenCalledWith('USER_PROFILE_UPDATE', expect.objectContaining({
        metadata: expect.objectContaining({ action: 'TENANT_CREATION_ATTEMPT' })
      }));
      expect(eventLogService.logEvent).toHaveBeenCalledWith('AUDIT_TRAIL_ACCESSED', expect.objectContaining({
        metadata: expect.objectContaining({ action: 'CREATE_TENANT' })
      }));
      // --- Step 2: Update Tenant ---
      // Sign a JWT token for the admin user
      const validJwtTokenAdmin = jwtService.sign({
        sub: mockAdminUser.id,
        id: mockAdminUser.id,
        tenantId: createdTenant.id, // Link to the tenant being updated
        sessionId: 'session-id-admin',
        mfa: false,
      }, { secret: process.env.JWT_SECRET ?? 'dev_jwt_secret_change_me' });
      // Mock RolesGuard (ADMIN/SUPER_ADMIN check for update) using mockImplementation
      (prismaService.userRole.findMany as jest.Mock).mockImplementation(({ where }) => {
        // Log the incoming arguments for debugging
        console.log('[TEST - Update Step] userRole.findMany called with where:', where);
        if (where?.userId === mockAdminUser.id && where?.role?.tenantId === createdTenant.id) { // Use nested role.tenantId
          console.log('[TEST - Update Step] Returning ADMIN role for UPDATE request.');
          return Promise.resolve([{ role: { name: 'ADMIN', isSystem: false, privileges: [] } }]);
        }
        // For any other user/tenant combination, return empty array
        console.log('[TEST - Update Step] Returning empty roles array for other user/tenant.');
        return Promise.resolve([]);
      });
      // Mock TenantGuard (isolation check) - Ensure requested slug 'lifecycle-test-tenant' resolves to 'createdTenant.id'
      (prismaService.tenant.findUnique as jest.Mock).mockResolvedValue({
          id: createdTenant.id,
          slug: createdTenant.slug,
          name: createdTenant.name,
          status: createdTenant.status,
          // ... potentially other fields the guard or subsequent logic might need
      });
      // Mock CsrfGuard session check for admin
      (prismaService.session.findUnique as jest.Mock).mockResolvedValue({
        id: 'session-id-admin',
        csrfToken: csrfTokens.admin, // <--- FIXED: Now matches cookie/header value
        userId: mockAdminUser.id,
        tenantId: createdTenant.id, // Links session to the tenant being updated
        revoked: false,
        expiresAt: new Date(Date.now() + 3600000),
      });
      // Mock the SERVICE call for update - THIS IS THE KEY CHANGE
      const updatedTenant = { ...createdTenant, ...validUpdateDto, updatedAt: new Date(Date.now() + 1000) };
      (tenantsService.update as jest.Mock).mockResolvedValue(updatedTenant);

      const updateResponse = await request(app.getHttpServer())
        .patch(`/v1/tenants/${createdTenant.slug}`)
        .set('Authorization', `Bearer ${validJwtTokenAdmin}`) // <--- Use the generated admin token
        .set('X-CSRF-Token', csrfTokens.admin) // <--- FIXED: Now matches cookie/DB value
        .set('Cookie', ['latch_session=session-id-admin', 'latch_csrf=csrf-token-admin'])
                .send(validUpdateDto)
        .expect(200);

      expect(updateResponse.body).toEqual(
        expect.objectContaining({
          id: updatedTenant.id,
          name: updatedTenant.name,
          slug: updatedTenant.slug,
          status: updatedTenant.status,
          branding: updatedTenant.branding,
          createdAt: expect.any(String),
          updatedAt: expect.any(String),
        })
      );

      // Verify audit logs for update (optional)
      expect(eventLogService.logEvent).toHaveBeenCalledWith('USER_PROFILE_UPDATE', expect.objectContaining({
        metadata: expect.objectContaining({ action: 'TENANT_UPDATE_ATTEMPT' })
      }));
      expect(eventLogService.logEvent).toHaveBeenCalledWith('USER_PROFILE_UPDATE', expect.objectContaining({
        metadata: expect.objectContaining({ action: 'UPDATE_TENANT' })
      }));
      // --- Step 3: Deactivate (Remove) Tenant ---
      // Sign token for super admin for deactivate step
      const validJwtTokenSuperAdmin2 = jwtService.sign({
        sub: mockSuperAdminUser.id,
        id: mockSuperAdminUser.id,
        tenantId: mockSuperAdminUser.tenantId,
        sessionId: 'session-id-super-admin-2', // Use a different session ID
        mfa: false,
      }, { secret: process.env.JWT_SECRET ?? 'dev_jwt_secret_change_me' });
      // Mock for deactivate step - RolesGuard
      (prismaService.userRole.findMany as jest.Mock).mockImplementation(({ where }) => {
        // Log the incoming arguments for debugging
        console.log('[TEST - Deactivate Step] userRole.findMany called with where:', where);

        // Check for TenantGuard's query structure first: { userId: ... }
        // This query is made by TenantGuard to check for system-level access or cross-tenant privileges.
        if (where?.userId === mockSuperAdminUser.id && !where?.role) {
             console.log('[TEST - Deactivate Step] Returning SUPER_ADMIN role for TenantGuard cross-tenant check.');
             // Return the role structure that TenantGuard expects for cross-tenant access (isSystem or privileges)
             return Promise.resolve([{ role: { name: 'SUPER_ADMIN', isSystem: true, privileges: ['cross_tenant_access'] } }]);
        }

        // Check for RolesGuard's query structure: { userId: ..., role: { tenantId: ... } }
        // This query is made by RolesGuard to check specific roles for the user on a specific tenant.
        if (where?.userId === mockSuperAdminUser.id && where?.role?.tenantId === mockSuperAdminUser.tenantId) {
          console.log('[TEST - Deactivate Step] Returning SUPER_ADMIN role for DEACTIVATE request (RolesGuard check).');
          return Promise.resolve([{ role: { name: 'SUPER_ADMIN', isSystem: true, privileges: ['cross_tenant_access'] } }]);
        }

        // For any other user/tenant combination, return empty array
        console.log('[TEST - Deactivate Step] Returning empty roles array for other user/tenant.');
        return Promise.resolve([]);
      });
      // Mock TenantGuard's secondary check for cross-tenant access for SUPER_ADMIN (this is the key fix)
      // The TenantGuard calls prisma.userRole.findMany({ where: { userId: req.user.id } }) to check for system roles/privileges
      // We need to mock this specific call structure *before* the request and ensure it runs only once.
      // This mock must be set *after* the RolesGuard mock (which uses mockImplementation and persists)
      // but will run *first* due to the execution order in the guards.
      // The RolesGuard mock (line ~449) handles where: { userId, role: { tenantId } }
      // This next mock handles where: { userId } for TenantGuard.
      (prismaService.userRole.findMany as jest.Mock).mockImplementationOnce(({ where }) => {
        console.log('[TEST - Deactivate Step - TenantGuard Check] userRole.findMany called with where:', where);
        // The TenantGuard calls with { userId: '...' }
        if (where?.userId === mockSuperAdminUser.id) {
          console.log('[TEST - Deactivate Step - TenantGuard Check] Returning SUPER_ADMIN role with cross-tenant access for TenantGuard.');
          // Return the role structure that TenantGuard expects for cross-tenant access (isSystem or privileges)
          // This role object does not need the nested role.tenantId for the TenantGuard's query.
          return Promise.resolve([{ role: { name: 'SUPER_ADMIN', isSystem: true, privileges: ['cross_tenant_access'] } }]);
        }
        // If it doesn't match, return empty, though it should match based on TenantGuard's call.
        console.log('[TEST - Deactivate Step - TenantGuard Check] Returning empty array (should not happen for TenantGuard call).');
        return Promise.resolve([]);
    });

    // Mock CsrfGuard session check
    (prismaService.session.findUnique as jest.Mock).mockResolvedValue({
      id: 'session-id-super-admin-2',
      csrfToken: csrfTokens.super2, // <--- FIXED: Now matches cookie/header value
      userId: mockSuperAdminUser.id,
      tenantId: mockSuperAdminUser.tenantId,
      revoked: false,
      expiresAt: new Date(Date.now() + 3600000),
    });

    (prismaService.tenant.findUnique as jest.Mock).mockResolvedValue(updatedTenant);
    // Mock the SERVICE call for remove - THIS IS THE KEY CHANGE
    const suspendedTenant = { ...updatedTenant, status: 'SUSPENDED', updatedAt: new Date(Date.now() + 2000) };
    (tenantsService.remove as jest.Mock).mockResolvedValue(suspendedTenant);

    const removeResponse = await request(app.getHttpServer())
      .delete(`/v1/tenants/${createdTenant.slug}`)
      .set('Authorization', `Bearer ${validJwtTokenSuperAdmin2}`) // <--- Use the new token
      .set('X-CSRF-Token', csrfTokens.super2) // <--- FIXED: Now matches cookie/DB value
      .set('Cookie', ['latch_session=session-id-super-admin-2', 'latch_csrf=csrf-token-super-admin-2'])
              .expect(200);

      expect(removeResponse.body).toEqual(
        expect.objectContaining({
          id: suspendedTenant.id,
          name: suspendedTenant.name,
          slug: suspendedTenant.slug,
          status: suspendedTenant.status,
          branding: suspendedTenant.branding,
          createdAt: expect.any(String),
          updatedAt: expect.any(String),
        })
      );

      expect(eventLogService.logEvent).toHaveBeenCalledWith('SESSION_REVOKE_ALL', expect.objectContaining({
        metadata: expect.objectContaining({ action: 'DEACTIVATE_TENANT' })
      }));
      // --- Step 4: Activate Tenant ---
      // Sign token for super admin for activate step
      const validJwtTokenSuperAdmin3 = jwtService.sign({
        sub: mockSuperAdminUser.id,
        id: mockSuperAdminUser.id,
        tenantId: mockSuperAdminUser.tenantId,
        sessionId: 'session-id-super-admin-3', // Use another different session ID
        mfa: false,
      }, { secret: process.env.JWT_SECRET ?? 'dev_jwt_secret_change_me' });
      // Mock for activate step - RolesGuard
            // Mock for activate step - RolesGuard AND TenantGuard
      (prismaService.userRole.findMany as jest.Mock).mockImplementation(({ where }) => {
        // Log the incoming arguments for debugging
        console.log('[TEST - Activate Step] userRole.findMany called with where:', where);

        // Check for TenantGuard's query structure first: { userId: ... }
        if (where?.userId === mockSuperAdminUser.id && !where?.role) {
             console.log('[TEST - Activate Step] Returning SUPER_ADMIN role for TenantGuard cross-tenant check.');
             return Promise.resolve([{ role: { name: 'SUPER_ADMIN', isSystem: true, privileges: ['cross_tenant_access'] } }]);
        }

        // Check for RolesGuard's query structure: { userId: ..., role: { tenantId: ... } }
        if (where?.userId === mockSuperAdminUser.id && where?.role?.tenantId === mockSuperAdminUser.tenantId) {
          console.log('[TEST - Activate Step] Returning SUPER_ADMIN role for ACTIVATE request (RolesGuard check).');
          return Promise.resolve([{ role: { name: 'SUPER_ADMIN', isSystem: true, privileges: ['cross_tenant_access'] } }]);
        }

        // For any other user/tenant combination, return empty array
        console.log('[TEST - Activate Step] Returning empty roles array for other user/tenant.');
        return Promise.resolve([]);
      });
      // Mock TenantGuard's secondary check for cross-tenant access for SUPER_ADMIN (this is the key fix)
            // Mock TenantGuard's secondary check for cross-tenant access for SUPER_ADMIN (this is the key fix)
            (prismaService.userRole.findMany as jest.Mock).mockImplementationOnce(({ where }) => {
                console.log('[TEST - Activate Step - TenantGuard Check] userRole.findMany called with where:', where);
                if (where?.userId === mockSuperAdminUser.id) {
                  console.log('[TEST - Activate Step - TenantGuard Check] Returning SUPER_ADMIN role with cross-tenant access for TenantGuard.');
                  return Promise.resolve([{ role: { name: 'SUPER_ADMIN', isSystem: true, privileges: ['cross_tenant_access'] } }]);
                }
                console.log('[TEST - Activate Step - TenantGuard Check] Returning empty array (should not happen for TenantGuard call).');
                return Promise.resolve([]);
            });
      
            (prismaService.session.findUnique as jest.Mock).mockResolvedValue({
              id: 'session-id-super-admin-3',
              csrfToken: csrfTokens.super3, // <--- FIXED: Now matches cookie/header value
              userId: mockSuperAdminUser.id,
              tenantId: mockSuperAdminUser.tenantId,
              revoked: false,
              expiresAt: new Date(Date.now() + 3600000),
            });
      
            (prismaService.tenant.findUnique as jest.Mock).mockResolvedValue(suspendedTenant);
            // Mock the SERVICE call for activate - THIS IS THE KEY CHANGE
            const activatedTenant = { ...suspendedTenant, status: 'ACTIVE', updatedAt: new Date(Date.now() + 3000) };
            (tenantsService.activate as jest.Mock).mockResolvedValue(activatedTenant);
      
            const activateResponse = await request(app.getHttpServer())
              .post(`/v1/tenants/${createdTenant.slug}/activate`)
              .set('Authorization', `Bearer ${validJwtTokenSuperAdmin3}`) // <--- Use the new token
              .set('X-CSRF-Token', csrfTokens.super3) // <--- FIXED: Now matches cookie/DB value
              .set('Cookie', ['latch_session=session-id-super-admin-3', 'latch_csrf=csrf-token-super-admin-3'])
                      .expect(201);

      expect(activateResponse.body).toEqual(
        expect.objectContaining({
          id: activatedTenant.id,
          name: activatedTenant.name,
          slug: activatedTenant.slug,
          status: activatedTenant.status,
          branding: activatedTenant.branding,
          createdAt: expect.any(String),
          updatedAt: expect.any(String),
        })
      );

      expect(eventLogService.logEvent).toHaveBeenCalledWith('LOGIN', expect.objectContaining({
        metadata: expect.objectContaining({ action: 'ACTIVATE_TENANT' })
      }));
           // --- Step 5: Read Tenant Details (Verify Final State) ---
      // Sign token for member user making the request
      const validJwtTokenMember = jwtService.sign({
        sub: 'user-member-id',
        id: 'user-member-id',
        tenantId: activatedTenant.id, // Links to the activated tenant
        sessionId: 'session-id-member',
        mfa: false,
      }, { secret: process.env.JWT_SECRET ?? 'dev_jwt_secret_change_me' });
      // Mock user roles for the member user making the request using mockImplementation
      (prismaService.userRole.findMany as jest.Mock).mockImplementation(({ where }) => {
        // Log the incoming arguments for debugging
        console.log('[TEST - Read Step] userRole.findMany called with where:', where);
        if (where?.userId === 'user-member-id' && where?.role?.tenantId === activatedTenant.id) { // Use nested role.tenantId
          console.log('[TEST - Read Step] Returning USER role for READ request.');
          return Promise.resolve([{ role: { name: 'USER', isSystem: false, privileges: [] } }]);
        }
        // For any other user/tenant combination, return empty array
        console.log('[TEST - Read Step] Returning empty roles array for other user/tenant.');
        return Promise.resolve([]);
      });
      // Mock TenantGuard (isolation check for findOne) - Ensure requested slug 'lifecycle-test-tenant' resolves to 'activatedTenant.id'
      // The guard will call prisma.tenant.findUnique({ where: { slug: activatedTenant.slug } })
      (prismaService.tenant.findUnique as jest.Mock).mockResolvedValue(activatedTenant); // Tenant exists and isolation passes based on slug lookup
      // Mock CsrfGuard session check for member
      (prismaService.session.findUnique as jest.Mock).mockResolvedValue({
        id: 'session-id-member',
        csrfToken: csrfTokens.member, // <--- FIXED: Now matches cookie/header value
        userId: 'user-member-id', // The ID of the user making the request (corresponds to mockTenantMemberUser)
        tenantId: activatedTenant.id, // Links session to the activated tenant
        revoked: false,
        expiresAt: new Date(Date.now() + 3600000),
      });
      // Mock the SERVICE call for findOne - THIS IS THE KEY CHANGE
      (tenantsService.findOne as jest.Mock).mockResolvedValue(activatedTenant);

      const readResponse = await request(app.getHttpServer())
        .get(`/v1/tenants/${activatedTenant.slug}`) // Use slug from activated tenant
        .set('Authorization', `Bearer ${validJwtTokenMember}`) // Provide valid member token
        .set('X-CSRF-Token', csrfTokens.member) // <--- FIXED: Now matches cookie/DB value
        .set('Cookie', ['latch_session=session-id-member', 'latch_csrf=csrf-token-member']) // Provide valid cookies
                .expect(200);

      expect(readResponse.body).toEqual(
        expect.objectContaining({
          id: activatedTenant.id,
          name: activatedTenant.name,
          slug: activatedTenant.slug,
          status: activatedTenant.status,
          branding: activatedTenant.branding,
          createdAt: expect.any(String),
          updatedAt: expect.any(String),
        })
      ); // Should reflect the final activated state

      // Verify audit logs for reading (optional)
      expect(eventLogService.logEvent).toHaveBeenCalledWith('USER_DATA_ACCESSED', expect.objectContaining({
        metadata: expect.objectContaining({ action: 'GET_TENANT' })
      }));
    });
    // Optional: Add a test for a partial lifecycle or a specific transition error
    // e.g., try to activate an already active tenant and expect BadRequestException
    it('should reject activating an already active tenant', async () => {
      // Sign token for super admin
      const validJwtTokenSuperAdmin = jwtService.sign({
        sub: mockSuperAdminUser.id,
        id: mockSuperAdminUser.id,
        tenantId: mockSuperAdminUser.tenantId,
        sessionId: 'session-id-super-admin-4', // Use a different session ID
        mfa: false,
      }, { secret: process.env.JWT_SECRET ?? 'dev_jwt_secret_change_me' });
      // Mock RolesGuard using mockImplementation
            // Mock RolesGuard AND TenantGuard for the reject test
      (prismaService.userRole.findMany as jest.Mock).mockImplementation(({ where }) => {
        // Log the incoming arguments for debugging
        console.log('[TEST - Reject Activate] userRole.findMany called with where:', where);

        // Check for TenantGuard's query structure first: { userId: ... }
        if (where?.userId === mockSuperAdminUser.id && !where?.role) {
             console.log('[TEST - Reject Activate] Returning SUPER_ADMIN role for TenantGuard cross-tenant check.');
             return Promise.resolve([{ role: { name: 'SUPER_ADMIN', isSystem: true, privileges: ['cross_tenant_access'] } }]);
        }

        // Check for RolesGuard's query structure: { userId: ..., role: { tenantId: ... } }
        if (where?.userId === mockSuperAdminUser.id && where?.role?.tenantId === mockSuperAdminUser.tenantId) {
          console.log('[TEST - Reject Activate] Returning SUPER_ADMIN role for ACTIVATE request (RolesGuard check).');
          return Promise.resolve([{ role: { name: 'SUPER_ADMIN', isSystem: true, privileges: ['cross_tenant_access'] } }]);
        }

        // For any other user/tenant combination, return empty array
        console.log('[TEST - Reject Activate] Returning empty roles array for other user/tenant.');
        return Promise.resolve([]);
      });
      // Mock TenantGuard's secondary check for cross-tenant access for SUPER_ADMIN (this is the key fix)
           // Mock TenantGuard's secondary check for cross-tenant access for SUPER_ADMIN (this is the key fix)
           (prismaService.userRole.findMany as jest.Mock).mockImplementationOnce(({ where }) => {
            console.log('[TEST - Reject Activate - TenantGuard Check] userRole.findMany called with where:', where);
            if (where?.userId === mockSuperAdminUser.id) {
              console.log('[TEST - Reject Activate - TenantGuard Check] Returning SUPER_ADMIN role with cross-tenant access for TenantGuard.');
              return Promise.resolve([{ role: { name: 'SUPER_ADMIN', isSystem: true, privileges: ['cross_tenant_access'] } }]);
            }
            console.log('[TEST - Reject Activate - TenantGuard Check] Returning empty array (should not happen for TenantGuard call).');
            return Promise.resolve([]);
        });
  
        // Mock CsrfGuard session check
        (prismaService.session.findUnique as jest.Mock).mockResolvedValue({
          id: 'session-id-super-admin-4',
          csrfToken: csrfTokens.super4, // <--- FIXED: Now matches cookie/header value
          userId: mockSuperAdminUser.id,
          tenantId: mockSuperAdminUser.tenantId,
          revoked: false,
          expiresAt: new Date(Date.now() + 3600000),
        });
        // Mock TenantGuard
        (prismaService.tenant.findUnique as jest.Mock).mockResolvedValue({ ...expectedCreatedTenant, id: 'generated-tenant-id-lifecycle', status: 'ACTIVE' }); // Tenant is already ACTIVE
        // Mock the service call to throw BadRequestException
        (tenantsService.activate as jest.Mock).mockRejectedValue(new BadRequestException('Tenant is already active'));
  
        // Make HTTP request to activate endpoint
        return request(app.getHttpServer())
          .post(`/v1/tenants/${expectedCreatedTenant.slug}/activate`) // Use slug from an existing ACTIVE tenant
          .set('Authorization', `Bearer ${validJwtTokenSuperAdmin}`)
          .set('X-CSRF-Token', csrfTokens.super4) // <--- FIXED: Now matches cookie/DB value
          .set('Cookie', ['latch_session=session-id-super-admin-4', 'latch_csrf=csrf-token-super-admin-4'])
          .expect(400); // Expect BadRequestException from service
    });
    // Optional: Test cache invalidation sequence
    // e.g., Create tenant -> call findAll (caches list) -> Update tenant -> call findAll again (should hit DB, not cache)
    // This requires mocking Redis calls (get, setex, del) within the service methods.
    it('should invalidate cache after update, forcing a fresh read on subsequent list', async () => {
      // ... (mock creation) ...
      // Call findAll, expect cache SETEX
      // ... (mock update, expect cache DEL calls) ...
      // Call findAll again, expect cache GET miss, DB call, new SETEX
      // This is complex and might be better suited for a service-level test focusing on cache logic.
    });
  });
  // Optional: Describe block for concurrent lifecycle tests (if applicable)
  // describe('Concurrent Lifecycle Events', () => { ... });
  // Optional: Describe block for error recovery lifecycle tests (if applicable)
  // describe('Error Recovery Lifecycle', () => { ... });
});