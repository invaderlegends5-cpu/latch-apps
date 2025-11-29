// src/admin/__tests__/admin.e2e.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { AppModule } from '@/app.module';
import { PrismaService } from '@/prisma/prisma.service';
import { EventLogService } from '@/events/event.service';
import { Redis } from 'ioredis';
import * as jwt from 'jsonwebtoken'; // Import jsonwebtoken
import { Request, Response, NextFunction } from 'express'; // Import Express types for middleware

// Simple middleware to parse Cookie header into req.cookies object
// This mimics the basic functionality of cookie-parser for this specific test scenario
function mockCookieParser(req: Request, res: Response, next: NextFunction) {
  if (req.headers.cookie) {
    // Split the Cookie header string by '; '
    const cookiePairs = req.headers.cookie.split('; ');
    req.cookies = req.cookies || {}; // Initialize if not already present
    for (const pair of cookiePairs) {
      const [key, ...valueParts] = pair.split('=');
      if (key && valueParts) {
        const value = valueParts.join('='); // Rejoin in case the original value had '=' in it
        req.cookies[key.trim()] = value.trim();
      }
    }
  }
  next();
}

interface JwtPayload {
  sub: string; // userId
  sessionId: string;
  tenantId: string;
  csrfToken?: string; // Optional, depending on your token structure
  mfa?: boolean;     // Optional, depending on your token structure
  iat?: number;
  exp?: number;
}

// Helper function to generate a valid JWT token for testing
// It's crucial that the secret used here matches the one your app uses for testing.
// This assumes JWT_SECRET is available in the test environment.
const generateValidJwtToken = (payload: JwtPayload): string => {
  const secret = process.env.JWT_SECRET ?? 'dev_jwt_secret_change_me'; // Match your app's secret
  // Set default iat and exp if not provided
  if (payload.iat === undefined) payload.iat = Math.floor(Date.now() / 1000);
  if (payload.exp === undefined) payload.exp = Math.floor(Date.now() / 1000) + 3600; // 1 hour default
  return jwt.sign(payload, secret);
};

describe('Admin E2E Tests', () => {
  let app: INestApplication;
  let prisma: PrismaService;
  let eventLogService: EventLogService;
  let redis: Redis;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    })
    .overrideProvider(PrismaService)
    .useValue({
      user: {
        findMany: jest.fn().mockResolvedValue([]), // Provide default
        count: jest.fn().mockResolvedValue(0), // Provide default
        findUnique: jest.fn().mockResolvedValue(null), // Provide default
        update: jest.fn().mockResolvedValue({}), // Provide default
      },
      userRole: {
        findMany: jest.fn().mockResolvedValue([]), // Provide default
        create: jest.fn().mockResolvedValue({}), // Provide default
        deleteMany: jest.fn().mockResolvedValue({ count: 0 }), // Provide default
        findUnique: jest.fn().mockResolvedValue(null), // Provide default
        // ADD missing aggregate method
        aggregate: jest.fn().mockResolvedValue({ _count: { id: 0 } }), // Provide default
      },
      // ADD missing rolePermission mock with aggregate
      rolePermission: {
        aggregate: jest.fn().mockResolvedValue({ _count: { id: 0 } }), // Provide default
      },
      role: {
        findMany: jest.fn().mockResolvedValue([]), // Provide default
        findUnique: jest.fn().mockResolvedValue(null), // Provide default
        groupBy: jest.fn().mockResolvedValue([]), // Provide default
        aggregate: jest.fn().mockResolvedValue({ _count: { id: 0 } }), // Provide default
      },
      event: {
        findMany: jest.fn().mockResolvedValue([]),
        findUnique: jest.fn(),
        findFirst: jest.fn(),
        create: jest.fn(),
        update: jest.fn(),
        delete: jest.fn(),
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
      session: { // ADD missing session mock
        findUnique: jest.fn().mockResolvedValue(null), // Provide default - CRITICAL FOR AUTH
        // update might be needed by JwtStrategy if it updates lastActiveAt
        update: jest.fn().mockResolvedValue({}), // Provide default
      },
      permission: {
        // Might be needed by other service methods, add if tests fail for related endpoints
        count: jest.fn().mockResolvedValue(0), // Provide default
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
      tenantRateLimitProfile: {
        findFirst: jest.fn().mockResolvedValue(null),
        findMany: jest.fn().mockResolvedValue([]),
        create: jest.fn(),
        update: jest.fn(),
        delete: jest.fn(),
      },
      // Add other models if needed by the specific admin endpoints tested
      $transaction: jest.fn().mockImplementation(async (callback) => {
        // Create a mock transaction object that mirrors the structure of the main prisma service
        // Ensure it includes ALL models/methods that might be used inside ANY transaction in your service.
        // For assignRoles, we need tx.userRole.deleteMany and tx.userRole.create.
        // For other operations (removeRoles, replaceRoles, temporaryAssignRoles, inheritRoles), tx.userRole.deleteMany and tx.userRole.create are also needed.
        // For the final findUnique call in each operation method, we need tx.user.findUnique WITH the correct 'include'.
        const tx = {
          tenant: {
            findUnique: jest.fn(),
            findMany: jest.fn(),
            create: jest.fn(),
            update: jest.fn(),
            count: jest.fn(),
          },
          event: {
            create: jest.fn(),
            findMany: jest.fn(),
            count: jest.fn(),
          },
          // ADD the userRole model mock to the transaction object
          userRole: {
            deleteMany: jest.fn().mockResolvedValue({ count: 0 }), // Often returns { count: number }
            create: jest.fn(),
            // Add other methods if other transactional operations use them, e.g., findMany, update
            findMany: jest.fn(),
            update: jest.fn(),
          },
          // ADD the user model mock for the final findUnique call in the operation methods
          user: {
            findUnique: jest.fn().mockResolvedValue({ // <-- CORRECT: Mock the return value structure
              id: 'mock-user-id', // Use a placeholder ID or make it dynamic if needed by the test logic
              name: 'Mock User Name',
              email: 'mock@example.com',
              tenantId: 'mock-tenant-id', // Use a placeholder or match expected tenant
              // CRITICAL: Include the 'roles' property as expected by the service logic's 'include' clause
              roles: [
                // Example: Mock an initial role, adjust based on test scenario if needed
                // {
                //   roleId: 'some-existing-role-id',
                //   role: { id: 'some-existing-role-id', name: 'SomeRole', ... }
                // }
                // For the ASSIGN operation test, this might initially be an empty array,
                // but the transaction logic adds to it. The service might expect the final state here.
                // Let's start with an empty array for the initial fetch before the transaction modifies roles.
              ],
              tenant: { id: 'mock-tenant-id', name: 'Mock Tenant', slug: 'mock-tenant' }, // Include tenant if the service logic accesses it
              // Add other user properties as needed by your service logic or assertions
            }),
            // Add other methods like findMany, update, etc., if used within transactions
          },
          // ADD the role model mock, as findMany is used in replaceRoles within the transaction
          role: {
            findMany: jest.fn(),
            // Add other methods if needed within transactions
          },
          // ADD the tenantPolicy model mock (if used in transactions)
          tenantPolicy: {
            findUnique: jest.fn(),
            upsert: jest.fn(),
            // Add other methods if used within transactions
          },
          // ADD any other models that might be used within transactions in AdminService
        };
      
        // Execute the callback function (the actual service logic) with the mocked transaction object
        return await callback(tx);
      }),
    })
    .overrideProvider(EventLogService)
    .useValue({
      logEvent: jest.fn().mockResolvedValue({}), // Provide default
      event$: {
        subscribe: jest.fn(), // Mock the subscribe method
      },
      // FIXED SYNTAX: Added 'data:' property name
      queryEvents: jest.fn().mockResolvedValue({ data: [], meta: { total: 0, limit: 10, offset: 0, hasNext: false } }), // Provide default
    })
    .overrideProvider('REDIS')
    .useValue({
      get: jest.fn().mockResolvedValue(null), // Provide default
      setex: jest.fn(), // Provide default
      del: jest.fn(), // Provide default
    })
    .compile();

    app = moduleFixture.createNestApplication();
    // --- APPLY THE MOCK COOKIE PARSER MIDDLEWARE ---
    app.use(mockCookieParser);
    // --- END MIDDLEWARE APPLICATION ---

    prisma = moduleFixture.get<PrismaService>(PrismaService);
    eventLogService = moduleFixture.get<EventLogService>(EventLogService);
    redis = moduleFixture.get<Redis>('REDIS');
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  describe('findAllUsers E2E', () => {
    beforeEach(() => {
      // Reset mocks before each test to avoid state carryover
      jest.clearAllMocks();
    });

    it('should return paginated users with valid authentication and authorization', async () => {
      // --- JWT Setup ---
      const userId = 'admin-user-id';
      const tenantId = 'tenant-id'; // The tenant ID associated with the user/session
      const sessionId = 'valid-session-id-for-findAllUsers';
      const csrfToken = 'valid-csrf-token';
      const payload: JwtPayload = {
        sub: userId,
        sessionId: sessionId, // Embed the session ID
        tenantId: tenantId, // Embed the tenant ID
        csrfToken: csrfToken, // Include if your strategy or other guards need it
        mfa: false,          // Include if your strategy needs it
      };
      const validToken = generateValidJwtToken(payload);

      // Mock the JWT validation flow (this happens first)
      // Mock session lookup for JwtStrategy.validate - THIS ID MUST MATCH THE ONE IN THE TOKEN
      jest.spyOn(prisma.session, 'findUnique').mockResolvedValue({
        id: sessionId, // <--- This must match payload.sessionId
        userId: userId,
        tenantId: tenantId, // <--- This tenantId must match the one used in TenantGuard
        csrfToken: csrfToken,
        revoked: false,
        createdAt: new Date(),
        lastActiveAt: new Date(),
        expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24),
        user: { id: userId, tenantId: tenantId } // Include if JwtStrategy attaches it
      });

      // --- End JWT Setup ---
      // Mock user lookup for JwtStrategy.validate (if it does a separate user fetch)
      // The default mock in beforeAll returns null. Override it here.
      jest.spyOn(prisma.user, 'findUnique').mockResolvedValue({
        id: 'admin-user-id',
        tenantId: 'tenant-id',
      });

      // Mock user roles for RolesGuard
      // The default mock in beforeAll returns []. Override it here.
      jest.spyOn(prisma.userRole, 'findMany').mockResolvedValue([
        {
          userId: 'admin-user-id',
          roleId: 'admin-role-id',
          role: {
            id: 'admin-role-id',
            name: 'ADMIN',
            tenantId: 'tenant-id',
            isSystem: false,
            isActive: true,
            createdAt: new Date(),
            validFrom: new Date(),
            validUntil: new Date(),
          },
        },
      ]);

      // --- Tenant Guard Setup ---
      // Mock tenant lookup for TenantGuard (based on x-tenant-slug header 'test-tenant')
      // The default mock in beforeAll returns null. Override it here.
      // Crucially, the 'id' returned here must match the 'tenantId' from the user's session/JWT payload.
      // The 'slug' must match the header value 'x-tenant-slug'.
      jest.spyOn(prisma.tenant, 'findUnique').mockResolvedValue({
        id: 'tenant-id', // <--- This ID must match the user's tenantId ('tenantId' variable)
        name: 'Test Tenant',
        slug: 'test-tenant', // This slug should match the header value 'x-tenant-slug'
        status: 'ACTIVE',
        createdAt: new Date(),
        updatedAt: new Date(),
      });
      // --- End Tenant Guard Setup ---

      // Mock the actual service call for AdminService.findAllUsers
      // The default mock in beforeAll returns []. Override it here.
      jest.spyOn(prisma.user, 'findMany').mockResolvedValue([
        {
          id: 'user-id',
          name: 'Test User',
          email: 'test@example.com',
          phone: '1234567890',
          tenantId: 'tenant-id',
          createdAt: new Date(),
          updatedAt: new Date(),
          isPhoneVerified: true,
          isEmailVerified: true,
          tenant: { id: 'tenant-id', name: 'Test Tenant', slug: 'test-tenant' },
          roles: [
            {
              role: {
                id: 'role-id',
                name: 'Admin',
                description: 'Admin role',
                isSystem: false,
                isActive: true,
                validFrom: new Date(),
                validUntil: new Date(Date.now() + 1000 * 60 * 60 * 24),
              },
            },
          ],
        },
      ]);
      // The default mock in beforeAll returns 0. Override it here.
      jest.spyOn(prisma.user, 'count').mockResolvedValue(1);

      const response = await request(app.getHttpServer())
        .get('/v1/admin/users?limit=50&offset=0&tenantId=tenant-id&includeRoleDetails=true')
        .set('Authorization', `Bearer ${validToken}`) // Use the generated token
        .set('x-csrf-token', 'valid-csrf-token')
        .set('x-tenant-slug', 'test-tenant') // This slug triggers TenantGuard
        // --- CORRECTED COOKIE FORMAT: Removed square brackets ---
        .set('Cookie', 'latch_session=valid-session-id; latch_csrf=valid-csrf-token')
        .expect(200);

      expect(response.body).toHaveProperty('data');
      expect(response.body).toHaveProperty('meta');
      expect(response.body.data).toBeInstanceOf(Array);
      expect(response.body.meta).toHaveProperty('total');
      expect(response.body.meta).toHaveProperty('limit');
      expect(response.body.meta).toHaveProperty('offset');
      expect(response.body.meta).toHaveProperty('hasNext');
    });

    it('should return 400 for invalid pagination parameters', async () => {
      // --- JWT Setup ---
      const userId = 'admin-user-id';
      const tenantId = 'tenant-id'; // The tenant ID associated with the user/session
      const sessionId = 'valid-session-id-for-findAllUsers-invalid';
      const csrfToken = 'valid-csrf-token';
      const payload: JwtPayload = {
        sub: userId,
        sessionId: sessionId, // Embed the session ID
        tenantId: tenantId, // Embed the tenant ID
        csrfToken: csrfToken, // Include if your strategy or other guards need it
        mfa: false,          // Include if your strategy needs it
      };
      const validToken = generateValidJwtToken(payload);

      // Mock the JWT validation flow (this happens first)
      // Mock session lookup for JwtStrategy.validate - THIS ID MUST MATCH THE ONE IN THE TOKEN
      jest.spyOn(prisma.session, 'findUnique').mockResolvedValue({
        id: sessionId, // <--- This must match payload.sessionId
        userId: userId,
        tenantId: tenantId, // <--- This tenantId must match the one used in TenantGuard
        csrfToken: csrfToken,
        revoked: false,
        createdAt: new Date(),
        lastActiveAt: new Date(),
        expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24),
        user: { id: userId, tenantId: tenantId } // Include if JwtStrategy attaches it
      });

      // --- End JWT Setup ---
      // Mock user lookup for JwtStrategy.validate
      jest.spyOn(prisma.user, 'findUnique').mockResolvedValue({
        id: 'admin-user-id',
        tenantId: 'tenant-id',
      });

      // Mock user roles for RolesGuard
      jest.spyOn(prisma.userRole, 'findMany').mockResolvedValue([
        {
          userId: 'admin-user-id',
          roleId: 'admin-role-id',
          role: {
            id: 'admin-role-id',
            name: 'ADMIN',
            tenantId: 'tenant-id',
            isSystem: false,
            isActive: true,
            createdAt: new Date(),
            validFrom: new Date(),
            validUntil: new Date(),
          },
        },
      ]);

      // --- Tenant Guard Setup ---
      // Mock tenant lookup for TenantGuard (based on x-tenant-slug header 'test-tenant')
      // Crucially, the 'id' returned here must match the 'tenantId' from the user's session/JWT payload.
      // The 'slug' must match the header value 'x-tenant-slug'.
      jest.spyOn(prisma.tenant, 'findUnique').mockResolvedValue({
        id: 'tenant-id', // <--- This ID must match the user's tenantId ('tenantId' variable)
        name: 'Test Tenant',
        slug: 'test-tenant', // This slug should match the header value 'x-tenant-slug'
        status: 'ACTIVE',
        createdAt: new Date(),
        updatedAt: new Date(),
      });
      // --- End Tenant Guard Setup ---

      const response = await request(app.getHttpServer())
        .get('/v1/admin/users?limit=150&offset=0') // Invalid limit
        .set('Authorization', `Bearer ${validToken}`) // Use the generated token
        .set('x-csrf-token', 'valid-csrf-token')
        .set('x-tenant-slug', 'test-tenant')
        // --- CORRECTED COOKIE FORMAT ---
        .set('Cookie', 'latch_session=valid-session-id; latch_csrf=valid-csrf-token')
        .expect(400);

      expect(response.body).toHaveProperty('message');
    });
  });

  // updateUserRole E2E
  describe('updateUserRole E2E', () => {
    beforeEach(() => {
      // Reset mocks before each test to avoid state carryover
      jest.clearAllMocks();
    });

    it('should update user roles successfully', async () => {
      // --- Define UUIDs ---
      const validTargetUserId = '11111111-1111-1111-1111-111111111111'; // Replace with a valid UUID
      const validTenantId = '22222222-2222-2222-2222-222222222222'; // Replace with a valid UUID
      const validRoleId = '33333333-3333-3333-3333-333333333333'; // Replace with a valid UUID
      // --- End UUIDs ---

      // --- JWT Setup ---
      const userId = 'admin-user-id';
      // The tenant ID associated with the admin user/session should also be a UUID if the DTO requires it for the admin user's tenantId.
      // Let's assume the admin user's tenantId is validTenantId for consistency in this test.
      const tenantId = validTenantId; // Use the UUID tenant ID
      const sessionId = 'valid-session-id-for-updateUserRole';
      const csrfToken = 'valid-csrf-token';
      const payload: JwtPayload = {
        sub: userId,
        sessionId: sessionId, // Embed the session ID
        tenantId: tenantId, // Embed the tenant ID (UUID)
        csrfToken: csrfToken, // Include if your strategy or other guards need it
        mfa: false,          // Include if your strategy needs it
      };
      const validToken = generateValidJwtToken(payload);

      // Mock the JWT validation flow (this happens first)
      // Mock session lookup for JwtStrategy.validate - THIS ID MUST MATCH THE ONE IN THE TOKEN
      jest.spyOn(prisma.session, 'findUnique').mockResolvedValue({
        id: sessionId, // <--- This must match payload.sessionId
        userId: userId,
        tenantId: tenantId, // <--- This tenantId must match the one used in TenantGuard (UUID)
        csrfToken: csrfToken,
        revoked: false,
        createdAt: new Date(),
        lastActiveAt: new Date(),
        expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24),
        user: { id: userId, tenantId: tenantId } // Include if JwtStrategy attaches it
      });

      // --- End JWT Setup ---
      // Mock user lookup for JwtStrategy.validate (admin user)
      jest.spyOn(prisma.user, 'findUnique').mockResolvedValue({
        id: 'admin-user-id',
        tenantId: tenantId, // Use the UUID tenant ID here too
      });

      // Mock user roles for RolesGuard (admin user roles)
      jest.spyOn(prisma.userRole, 'findMany').mockResolvedValue([
        {
          userId: 'admin-user-id',
          roleId: 'admin-role-id',
          role: {
            id: 'admin-role-id',
            name: 'ADMIN',
            tenantId: tenantId, // Use the UUID tenant ID here too
            isSystem: false,
            isActive: true,
            createdAt: new Date(),
            validFrom: new Date(),
            validUntil: new Date(),
          },
        },
      ]);

      // --- Tenant Guard Setup ---
      // Mock tenant lookup for TenantGuard (based on x-tenant-slug header 'test-tenant')
      // Crucially, the 'id' returned here must match the 'tenantId' from the user's session/JWT payload (UUID).
      // The 'slug' must match the header value 'x-tenant-slug'.
      jest.spyOn(prisma.tenant, 'findUnique').mockResolvedValue({
        id: tenantId, // <--- This ID (UUID) must match the user's tenantId ('tenantId' variable)
        name: 'Test Tenant',
        slug: 'test-tenant', // This slug should match the header value 'x-tenant-slug'
        status: 'ACTIVE',
        createdAt: new Date(),
        updatedAt: new Date(),
      });
      // --- End Tenant Guard Setup ---

      // Mock service calls for updateUserRole logic
      // Mock finding the target user (using the UUID)
      jest.spyOn(prisma.user, 'findUnique').mockResolvedValueOnce({
        id: validTargetUserId, // Use the UUID
        tenantId: tenantId, // Use the UUID tenant ID
        roles: [],
        tenant: { id: tenantId, name: 'Test Tenant', slug: 'test-tenant' }, // Use the UUID tenant ID
      });
      // Mock finding the role to assign (using the UUID)
      jest.spyOn(prisma.role, 'findMany').mockResolvedValue([
        {
          id: validRoleId, // Use the UUID
          tenantId: tenantId, // Use the UUID tenant ID
          name: 'Admin',
          description: 'Admin role',
          isSystem: false,
          isActive: true,
          createdAt: new Date(),
          validFrom: new Date(),
          validUntil: new Date(),
        },
      ]);
      // Mock creating the user-role assignment (using the UUIDs)
      jest.spyOn(prisma.userRole, 'create').mockResolvedValue({
        userId: validTargetUserId, // Use the UUID
        roleId: validRoleId, // Use the UUID
        createdAt: new Date(),
        validFrom: new Date(),
        validUntil: new Date(Date.now() + 1000 * 60 * 60 * 24),
      });

      const response = await request(app.getHttpServer())
        .patch('/v1/admin/users/roles')
        .set('Authorization', `Bearer ${validToken}`) // Use the generated token
        .set('x-csrf-token', 'valid-csrf-token')
        .set('x-tenant-slug', 'test-tenant') // This slug triggers TenantGuard
        // --- CORRECTED COOKIE FORMAT ---
        .set('Cookie', 'latch_session=valid-session-id; latch_csrf=valid-csrf-token')
        .send({
          userId: validTargetUserId, // Use a valid UUID
          tenantId: tenantId,        // Use a valid UUID (the admin's tenant ID)
          operation: 'ASSIGN',
          roles: [{ roleId: validRoleId }], // Use a valid UUID
        });
        // --- DEBUG LOGS ---
        console.log("updateUserRole response status:", response.status);
        console.log("updateUserRole response body:", response.body);
        // --- END DEBUG LOGS ---

      // Expect 200 after checking the logs
      expect(response.status).toBe(200);

      expect(response.body).toHaveProperty('message');
      expect(response.body.message).toContain('Roles assigned successfully');
    });

    it('should return 400 for invalid operation type', async () => {
       // --- Define UUIDs ---
       const validTargetUserId = '44444444-4444-4444-4444-444444444444'; // Different UUID for this test
       const validTenantId = '22222222-2222-2222-2222-222222222222'; // Same tenant ID as first test
       const validRoleId = '55555555-5555-5555-5555-555555555555'; // Different UUID for this test
       // --- End UUIDs ---

       // --- JWT Setup ---
       const userId = 'admin-user-id';
       // The tenant ID associated with the admin user/session should also be a UUID if the DTO requires it for the admin user's tenantId.
       // Let's assume the admin user's tenantId is validTenantId for consistency in this test.
       const tenantId = validTenantId; // Use the UUID tenant ID
       const sessionId = 'valid-session-id-for-updateUserRole-invalid';
       const csrfToken = 'valid-csrf-token';
       const payload: JwtPayload = {
         sub: userId,
         sessionId: sessionId, // Embed the session ID
         tenantId: tenantId, // Embed the tenant ID (UUID)
         csrfToken: csrfToken, // Include if your strategy or other guards need it
         mfa: false,          // Include if your strategy needs it
       };
       const validToken = generateValidJwtToken(payload);

       // Mock the JWT validation flow (this happens first)
       // Mock session lookup for JwtStrategy.validate - THIS ID MUST MATCH THE ONE IN THE TOKEN
       jest.spyOn(prisma.session, 'findUnique').mockResolvedValue({
         id: sessionId, // <--- This must match payload.sessionId
         userId: userId,
         tenantId: tenantId, // <--- This tenantId must match the one used in TenantGuard (UUID)
         csrfToken: csrfToken,
         revoked: false,
         createdAt: new Date(),
         lastActiveAt: new Date(),
         expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24),
         user: { id: userId, tenantId: tenantId } // Include if JwtStrategy attaches it
       });

       // --- End JWT Setup ---
      // Mock user lookup for JwtStrategy.validate (admin user)
      jest.spyOn(prisma.user, 'findUnique').mockResolvedValue({
        id: 'admin-user-id',
        tenantId: tenantId, // Use the UUID tenant ID here too
      });

      // Mock user roles for RolesGuard (admin user roles)
      jest.spyOn(prisma.userRole, 'findMany').mockResolvedValue([
        {
          userId: 'admin-user-id',
          roleId: 'admin-role-id',
          role: {
            id: 'admin-role-id',
            name: 'ADMIN',
            tenantId: tenantId, // Use the UUID tenant ID here too
            isSystem: false,
            isActive: true,
            createdAt: new Date(),
            validFrom: new Date(),
            validUntil: new Date(),
          },
        },
      ]);

      // --- Tenant Guard Setup ---
      // Mock tenant lookup for TenantGuard (based on x-tenant-slug header 'test-tenant')
      // Crucially, the 'id' returned here must match the 'tenantId' from the user's session/JWT payload (UUID).
      // The 'slug' must match the header value 'x-tenant-slug'.
      jest.spyOn(prisma.tenant, 'findUnique').mockResolvedValue({
        id: tenantId, // <--- This ID (UUID) must match the user's tenantId ('tenantId' variable)
        name: 'Test Tenant',
        slug: 'test-tenant', // This slug should match the header value 'x-tenant-slug'
        status: 'ACTIVE',
        createdAt: new Date(),
        updatedAt: new Date(),
      });
      // --- End Tenant Guard Setup ---

      // Mock service calls for updateUserRole logic *for the invalid operation test*
      // Mock finding the target user (using the UUID) - This might be called depending on service logic
      jest.spyOn(prisma.user, 'findUnique').mockResolvedValueOnce({
        id: validTargetUserId, // Use the UUID
        tenantId: tenantId, // Use the UUID tenant ID
        roles: [],
        tenant: { id: tenantId, name: 'Test Tenant', slug: 'test-tenant' }, // Use the UUID tenant ID
      });
      // Mock finding the role to assign (using the UUID) - This might be called depending on service logic
      jest.spyOn(prisma.role, 'findMany').mockResolvedValue([
        {
          id: validRoleId, // Use the UUID
          tenantId: tenantId, // Use the UUID tenant ID
          name: 'Admin',
          description: 'Admin role',
          isSystem: false,
          isActive: true,
          createdAt: new Date(),
          validFrom: new Date(),
          validUntil: new Date(),
        },
      ]);

      const response = await request(app.getHttpServer())
        .patch('/v1/admin/users/roles')
        .set('Authorization', `Bearer ${validToken}`) // Use the generated token
        .set('x-csrf-token', 'valid-csrf-token')
        .set('x-tenant-slug', 'test-tenant')
        // --- CORRECTED COOKIE FORMAT ---
        .set('Cookie', 'latch_session=valid-session-id; latch_csrf=valid-csrf-token')
        .send({
          userId: validTargetUserId, // Use a valid UUID
          tenantId: tenantId,        // Use a valid UUID (the admin's tenant ID)
          operation: 'INVALID_OPERATION', // Invalid operation
          roles: [{ roleId: validRoleId }], // Use a valid UUID
        })
        .expect(400); // Expect 400 because operation is invalid, but UUIDs are valid

      expect(response.body).toHaveProperty('message');
    });
  });

  describe('getAuditEvents E2E', () => {
    beforeEach(() => {
      // Reset mocks before each test to avoid state carryover
      jest.clearAllMocks();
    });

    it('should return paginated audit events', async () => {
      // --- JWT Setup ---
      const userId = 'admin-user-id';
      const tenantId = 'tenant-id'; // The tenant ID associated with the user/session
      const sessionId = 'valid-session-id-for-getAuditEvents';
      const csrfToken = 'valid-csrf-token';
      const payload: JwtPayload = {
        sub: userId,
        sessionId: sessionId, // Embed the session ID
        tenantId: tenantId, // Embed the tenant ID
        csrfToken: csrfToken, // Include if your strategy or other guards need it
        mfa: false,          // Include if your strategy needs it
      };
      const validToken = generateValidJwtToken(payload);

      // Mock the JWT validation flow (this happens first)
      // Mock session lookup for JwtStrategy.validate - THIS ID MUST MATCH THE ONE IN THE TOKEN
      jest.spyOn(prisma.session, 'findUnique').mockResolvedValue({
        id: sessionId, // <--- This must match payload.sessionId
        userId: userId,
        tenantId: tenantId, // <--- This tenantId must match the one used in TenantGuard
        csrfToken: csrfToken,
        revoked: false,
        createdAt: new Date(),
        lastActiveAt: new Date(),
        expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24),
        user: { id: userId, tenantId: tenantId } // Include if JwtStrategy attaches it
      });

      // --- End JWT Setup ---
      // Mock user lookup for JwtStrategy.validate
      jest.spyOn(prisma.user, 'findUnique').mockResolvedValue({
        id: 'admin-user-id',
        tenantId: 'tenant-id',
      });

      // Mock user roles for RolesGuard
      jest.spyOn(prisma.userRole, 'findMany').mockResolvedValue([
        {
          userId: 'admin-user-id',
          roleId: 'admin-role-id',
          role: {
            id: 'admin-role-id',
            name: 'ADMIN',
            tenantId: 'tenant-id',
            isSystem: false,
            isActive: true,
            createdAt: new Date(),
            validFrom: new Date(),
            validUntil: new Date(),
          },
        },
      ]);

      // --- Tenant Guard Setup ---
      // Mock tenant lookup for TenantGuard (based on x-tenant-slug header 'test-tenant')
      // Crucially, the 'id' returned here must match the 'tenantId' from the user's session/JWT payload.
      // The 'slug' must match the header value 'x-tenant-slug'.
      jest.spyOn(prisma.tenant, 'findUnique').mockResolvedValue({
        id: 'tenant-id', // <--- This ID must match the user's tenantId ('tenantId' variable)
        name: 'Test Tenant',
        slug: 'test-tenant', // This slug should match the header value 'x-tenant-slug'
        status: 'ACTIVE',
        createdAt: new Date(),
        updatedAt: new Date(),
      });
      // --- End Tenant Guard Setup ---

      const mockEvents = {
        // FIXED SYNTAX: Added 'data:' property name
        data: [],
        meta: { total: 0, limit: 50, offset: 0, hasNext: false },
      };
      // Mock the service call for EventLogService.queryEvents
      jest.spyOn(eventLogService, 'queryEvents').mockResolvedValue(mockEvents);

      const response = await request(app.getHttpServer())
        .get('/v1/admin/audit/events?limit=50&offset=0&type=USER_PROFILE_UPDATE')
        .set('Authorization', `Bearer ${validToken}`) // Use the generated token
        .set('x-csrf-token', 'valid-csrf-token')
        .set('x-tenant-slug', 'test-tenant')
        // --- CORRECTED COOKIE FORMAT ---
        .set('Cookie', 'latch_session=valid-session-id; latch_csrf=valid-csrf-token')
        .expect(200);

      expect(response.body).toHaveProperty('data');
      expect(response.body).toHaveProperty('meta');
    });
  });

  describe('getRoleAnalytics E2E', () => {
    beforeEach(() => {
      // Reset mocks before each test to avoid state carryover
      jest.clearAllMocks();
    });

    it('should return role analytics for a tenant', async () => {
      // --- JWT Setup ---
      const userId = 'admin-user-id';
      const tenantId = 'tenant-id'; // The tenant ID associated with the user/session
      const sessionId = 'valid-session-id-for-getRoleAnalytics';
      const csrfToken = 'valid-csrf-token';
      const payload: JwtPayload = {
        sub: userId,
        sessionId: sessionId, // Embed the session ID
        tenantId: tenantId, // Embed the tenant ID
        csrfToken: csrfToken, // Include if your strategy or other guards need it
        mfa: false,          // Include if your strategy needs it
      };
      const validToken = generateValidJwtToken(payload);

      // Mock the JWT validation flow (this happens first)
      // Mock session lookup for JwtStrategy.validate - THIS ID MUST MATCH THE ONE IN THE TOKEN
      jest.spyOn(prisma.session, 'findUnique').mockResolvedValue({
        id: sessionId, // <--- This must match payload.sessionId
        userId: userId,
        tenantId: tenantId, // <--- This tenantId must match the one used in TenantGuard
        csrfToken: csrfToken,
        revoked: false,
        createdAt: new Date(),
        lastActiveAt: new Date(),
        expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24),
        user: { id: userId, tenantId: tenantId } // Include if JwtStrategy attaches it
      });

      // --- End JWT Setup ---
      // Mock user lookup for JwtStrategy.validate
      jest.spyOn(prisma.user, 'findUnique').mockResolvedValue({
        id: 'admin-user-id',
        tenantId: 'tenant-id',
      });

      // Mock user roles for RolesGuard
      jest.spyOn(prisma.userRole, 'findMany').mockResolvedValue([
        {
          userId: 'admin-user-id',
          roleId: 'admin-role-id',
          role: {
            id: 'admin-role-id',
            name: 'ADMIN',
            tenantId: 'tenant-id',
            isSystem: false,
            isActive: true,
            createdAt: new Date(),
            validFrom: new Date(),
            validUntil: new Date(),
          },
        },
      ]);

      // --- Tenant Guard Setup ---
      // Tenant lookup for TenantGuard (using :tenantId param in this route)
      // The route uses /analytics/roles/:tenantId. The guard likely looks up by the ID in the param.
      // Mock tenant lookup for the :tenantId parameter 'tenant-id'.
      // Crucially, the 'id' returned here must match the 'tenantId' parameter in the URL.
      // It should also match the user's tenantId for isolation.
      jest.spyOn(prisma.tenant, 'findUnique').mockResolvedValue({
        id: 'tenant-id', // <--- This ID must match the :tenantId param 'tenant-id' AND the user's tenantId
        name: 'Test Tenant',
        slug: 'test-tenant-slug', // Doesn't matter for this specific param lookup, but good to have
        status: 'ACTIVE',
        createdAt: new Date(),
        updatedAt: new Date(),
      });
      // --- End Tenant Guard Setup ---

      const mockTenant = { id: 'tenant-id' };
      const mockRoleStats = [{ name: 'Admin', _count: 1, _avg: { priority: 1 } }];
      const mockUserRoleStats = { _count: { id: 1, userId: 1, roleId: 1 } };
      const mockPermissionStats = { _count: { id: 1 } };
      // Mock service calls for AdminService.getRoleAnalytics
      jest.spyOn(prisma.tenant, 'findUnique').mockResolvedValueOnce(mockTenant); // For service check - This might conflict if called again with different args
      jest.spyOn(prisma.role, 'groupBy').mockResolvedValue(mockRoleStats);
      jest.spyOn(prisma.userRole, 'aggregate').mockResolvedValue(mockUserRoleStats);
      jest.spyOn(prisma.rolePermission, 'aggregate').mockResolvedValue(mockPermissionStats);

      const response = await request(app.getHttpServer())
        .get('/v1/admin/analytics/roles/tenant-id') // Uses :tenantId param
        .set('Authorization', `Bearer ${validToken}`) // Use the generated token
        .set('x-csrf-token', 'valid-csrf-token')
        .set('x-tenant-slug', 'test-tenant') // TenantGuard might also validate against header
        // --- CORRECTED COOKIE FORMAT ---
        .set('Cookie', 'latch_session=valid-session-id; latch_csrf=valid-csrf-token')
        .expect(200);

      expect(response.body).toHaveProperty('roleDistribution');
      expect(response.body).toHaveProperty('userRoleStats');
      expect(response.body).toHaveProperty('permissionStats');
      expect(response.body).toHaveProperty('timestamp');
    });
  });

  describe('bulkUpdateUserRoles E2E', () => {
    beforeEach(() => {
      // Reset mocks before each test to avoid state carryover
      jest.clearAllMocks();
    });

    it('should perform bulk role updates successfully', async () => {
      // --- JWT Setup for bulkUpdateUserRoles ---
      const userId = 'admin-user-id';
      const tenantId = 'tenant-id'; // Or use a UUID if the admin's tenantId must be a UUID for this endpoint
      const sessionId = 'valid-session-id-for-bulkUpdateUserRoles';
      const csrfToken = 'valid-csrf-token';
      const payload: JwtPayload = {
        sub: userId,
        sessionId: sessionId, // Embed the session ID
        tenantId: tenantId, // Embed the tenant ID
        csrfToken: csrfToken, // Include if your strategy or other guards need it
        mfa: false,          // Include if your strategy needs it
      };
      const validToken = generateValidJwtToken(payload);

      // Mock the JWT validation flow (this happens first)
      // Mock session lookup for JwtStrategy.validate - THIS ID MUST MATCH THE ONE IN THE TOKEN
      jest.spyOn(prisma.session, 'findUnique').mockResolvedValue({
        id: sessionId, // <--- This must match payload.sessionId
        userId: userId,
        tenantId: tenantId, // <--- This tenantId must match the one used in TenantGuard
        csrfToken: csrfToken,
        revoked: false,
        createdAt: new Date(),
        lastActiveAt: new Date(),
        expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24),
        user: { id: userId, tenantId: tenantId } // Include if JwtStrategy attaches it
      });

      // --- End JWT Setup ---
      // Mock user lookup for JwtStrategy.validate (admin user)
      jest.spyOn(prisma.user, 'findUnique').mockResolvedValue({
        id: 'admin-user-id',
        tenantId: tenantId, // Use the tenantId
      });

      // Mock user roles for RolesGuard (admin user roles)
      jest.spyOn(prisma.userRole, 'findMany').mockResolvedValue([
        {
          userId: 'admin-user-id',
          roleId: 'admin-role-id',
          role: {
            id: 'admin-role-id',
            name: 'ADMIN',
            tenantId: tenantId, // Use the tenantId
            isSystem: false,
            isActive: true,
            createdAt: new Date(),
            validFrom: new Date(),
            validUntil: new Date(),
          },
        },
      ]);

      // --- Tenant Guard Setup ---
      // Mock tenant lookup for TenantGuard (based on x-tenant-slug header 'test-tenant')
      // Crucially, the 'id' returned here must match the 'tenantId' from the user's session/JWT payload.
      // The 'slug' must match the header value 'x-tenant-slug'.
      jest.spyOn(prisma.tenant, 'findUnique').mockResolvedValue({
        id: tenantId, // <--- This ID must match the user's tenantId ('tenantId' variable)
        name: 'Test Tenant',
        slug: 'test-tenant', // This slug should match the header value 'x-tenant-slug'
        status: 'ACTIVE',
        createdAt: new Date(),
        updatedAt: new Date(),
      });
      // --- End Tenant Guard Setup ---

      // Mock service calls for AdminService.bulkUpdateUserRoles (example mocks)
      // You need to mock the specific calls made by bulkUpdateUserRoles
      // e.g., prisma.user.findMany, prisma.role.findMany, prisma.userRole.createMany, etc.
      // depending on the implementation.
      // Example:
      jest.spyOn(prisma.user, 'findMany').mockResolvedValue([
        { id: '11111111-1111-1111-1111-111111111111', tenantId: tenantId },
        { id: '22222222-2222-2222-2222-222222222222', tenantId: tenantId },
      ]);
      jest.spyOn(prisma.role, 'findMany').mockResolvedValue([
        { id: '33333333-3333-3333-3333-333333333333', tenantId: tenantId },
        { id: '44444444-4444-4444-4444-444444444444', tenantId: tenantId },
      ]);
      // Mock the bulk operation itself if needed, or mock the final return value
      // depending on how the service method is structured.
      // For now, let's assume it returns a structure like this on success:
      const mockBulkResult = {
        totalUsers: 2,
        successfulUpdates: 2,
        failedUpdates: 0,
        results: [
          { userId: '11111111-1111-1111-1111-111111111111', roleId: '33333333-3333-3333-3333-333333333333', status: 'SUCCESS' },
          { userId: '22222222-2222-2222-2222-222222222222', roleId: '44444444-4444-4444-4444-444444444444', status: 'SUCCESS' },
        ],
      };
      // You might need to spy on the AdminService method directly if it doesn't use Prisma directly for the final result.
      // For now, assume Prisma mocks lead to success and the service returns the expected structure.

      const response = await request(app.getHttpServer())
        .post('/v1/admin/users/bulk/roles')
        .set('Authorization', `Bearer ${validToken}`) // Now 'validToken' is defined
        .set('x-csrf-token', 'valid-csrf-token')
        .set('x-tenant-slug', 'test-tenant')
        // --- CORRECTED COOKIE FORMAT ---
        .set('Cookie', 'latch_session=valid-session-id; latch_csrf=valid-csrf-token')
        .send({
          // IMPORTANT: Check the BulkUpdateUserRolesDto for UUID requirements too!
          // Example: If userIds and roleIds need to be UUIDs, use them.
          // Using placeholder UUIDs for now - replace with actual valid ones if required by the DTO.
          userIds: ['11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222'],
          roleIds: ['33333333-3333-3333-3333-333333333333', '44444444-4444-4444-4444-444444444444'],
          operation: 'ASSIGN', // Check if this operation is valid for bulk updates too
          reason: 'Bulk assignment',
        })
        .expect(201); // Expect 201 as discussed

      expect(response.body).toHaveProperty('totalUsers');
      expect(response.body).toHaveProperty('successfulUpdates');
      expect(response.body).toHaveProperty('failedUpdates');
      expect(response.body).toHaveProperty('results');
    });
  });
});