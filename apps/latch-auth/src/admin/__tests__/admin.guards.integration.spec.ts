// admin.guards.integration.spec.ts

import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { AppModule } from '@/app.module';
import { PrismaService } from '@/prisma/prisma.service';
import { EventLogService } from '@/events/event.service';
import * as jwt from 'jsonwebtoken'; // Import jsonwebtoken
import { Request, Response, NextFunction } from 'express'; // Import Express types for middleware
import { TestAppModule } from '@/tests/test-app.module';
import { RateLimitingService } from '@/rate-limiting/rate-limiting.service';
import { SecurityMonitoringService } from '@/security/security-monitor.service';
import { BehavioralAnalysisService } from '@/behavioral-analysis/behavioral-analysis.service';
import { BotDetectionService } from '@/bot-detection/bot-detection.service';
import { DeviceFingerprintingService } from '@/device-fingerprinting/device-fingerprinting.service';
import { IPReputationService } from '@/ip-reputation/ip-reputation.service';

// Define a type for the token payload if needed for clarity
interface JwtPayload {
  sub: string; // userId
  sessionId: string;
  tenantId: string;
  csrfToken: string;
  iat?: number;
  exp?: number;
}

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

describe('Admin Guard Integration Tests', () => {
  let app: INestApplication;
  let prisma: PrismaService;
  let eventLogService: EventLogService;

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

//   beforeAll(async () => {
//     const moduleFixture: TestingModule = await Test.createTestingModule({
//       imports: [TestAppModule], // Ensure AppModule provides JwtStrategy and PassportModule
//     })
//     .overrideProvider(PrismaService)
//     .useValue({
//   session: {
//     findUnique: jest.fn((args: any) => {
//       // Your existing session mock logic
//       const requestedId = args.where?.id;
//       if (requestedId === 'session-id-super') {
//         return Promise.resolve({
//           id: 'session-id-super',
//           csrfToken: 'valid-csrf-token',
//           userId: 'super-admin-id',
//           tenantId: 'system-tenant',
//           revoked: false,
//           expiresAt: new Date(Date.now() + 100000),
//           ipAddress: '127.0.0.1',
//           userAgent: 'test-agent',
//           lastActiveAt: new Date(),
//           createdAt: new Date(),
//           updatedAt: new Date(),
//           user: { id: 'super-admin-id', phone: '1234567890', tenantId: 'system-tenant' }
//         });
//       } else if (requestedId === 'session-id') {
//         return Promise.resolve({
//           id: 'session-id',
//           csrfToken: 'valid-csrf-token',
//           userId: 'admin-id',
//           tenantId: 'tenant-123',
//           revoked: false,
//           expiresAt: new Date(Date.now() + 100000),
//           ipAddress: '127.0.0.1',
//           userAgent: 'test-agent',
//           lastActiveAt: new Date(),
//           createdAt: new Date(),
//           updatedAt: new Date(),
//           user: { id: 'admin-id', phone: '1234567890', tenantId: 'tenant-123' }
//         });
//       } else if (requestedId === 'session-id-user') {
//         return Promise.resolve({
//           id: 'session-id-user',
//           csrfToken: 'valid-csrf-token',
//           userId: 'user-id',
//           tenantId: 'tenant-456',
//           revoked: false,
//           expiresAt: new Date(Date.now() + 100000),
//           ipAddress: '127.0.0.1',
//           userAgent: 'test-agent',
//           lastActiveAt: new Date(),
//           createdAt: new Date(),
//           updatedAt: new Date(),
//           user: { id: 'user-id', phone: '1234567890', tenantId: 'tenant-456' }
//         });
//       }
//       return Promise.resolve(null);
//     }),
//     // ADD THE MISSING findMany METHOD that DeviceFingerprintingService needs
//     findMany: jest.fn().mockResolvedValue([]), // This fixes the DeviceFingerprintingService initialization error
//   },
//   userRole: {
//     findMany: jest.fn((args: any) => {
//       // Your existing mock
//       return Promise.resolve([]);
//     }),
//   },
//   tenant: {
//     findMany: jest.fn(),
//     findUnique: jest.fn(() => Promise.resolve({
//       id: 'system-tenant',
//       slug: 'system-tenant',
//       name: 'System Tenant',
//       status: 'ACTIVE',
//       branding: {},
//       createdAt: new Date(),
//       updatedAt: new Date()
//     })),
//     count: jest.fn(() => Promise.resolve(10)),
//     create: jest.fn((args: any) => {
//       return Promise.resolve({
//         id: 'new-tenant-id-' + Date.now(),
//         name: args.data.name,
//         slug: args.data.slug,
//         status: args.data.status || 'ACTIVE',
//         branding: args.data.branding || {},
//         createdAt: new Date(),
//         updatedAt: new Date(),
//       });
//     }),
//     update: jest.fn(),
//     delete: jest.fn(),
//   },
//   user: {
//     findUnique: jest.fn(),
//     findMany: jest.fn(),  // Add this
//     count: jest.fn(),    // Add this
//     create: jest.fn(),
//     update: jest.fn(),
//     delete: jest.fn(),
//     findFirst: jest.fn(),
//   },
//   tenantRateLimitProfile: {
//     findFirst: jest.fn().mockResolvedValue(null),
//     findMany: jest.fn().mockResolvedValue([]),
//     create: jest.fn(),
//     update: jest.fn(),
//     delete: jest.fn(),
//   },
//   // ADD THE MISSING event model
//   event: {
//     findMany: jest.fn().mockResolvedValue([]),
//     findUnique: jest.fn(),
//     findFirst: jest.fn(),
//     create: jest.fn(),
//     update: jest.fn(),
//     delete: jest.fn(),
//     count: jest.fn(),
//   },
//   // ADD THE MISSING iPBlock model - fixes the runtime error
//   iPBlock: {
//     findFirst: jest.fn().mockResolvedValue(null), // Return null if IP not blocked
//     findMany: jest.fn().mockResolvedValue([]),
//     create: jest.fn(),
//     update: jest.fn(),
//     delete: jest.fn(),
//     upsert: jest.fn(),
//   },
//   // Add other required methods
//   $connect: jest.fn(),
//   $disconnect: jest.fn(),

//   role: {
//     findMany: jest.fn(),
//   }
// })
//     .overrideProvider(EventLogService) // Mock EventLogService
//     .useValue({
//       logEvent: jest.fn(),
//       queryEvents: jest.fn(), // Might be needed if getAuditEvents is called
//       event$: {
//         subscribe: jest.fn(), // Mock the subscribe method
//       },
//     })
//     // JwtStrategy is NOT overridden, so the real one is used and registers the 'jwt' strategy
//     .compile();

//     app = moduleFixture.createNestApplication();
//     // Apply the mockCookieParser middleware before NestJS routes/guards are executed
//     // This ensures req.cookies is populated before CsrfGuard runs
//     app.use(mockCookieParser);

//     prisma = moduleFixture.get<PrismaService>(PrismaService);
//     eventLogService = moduleFixture.get<EventLogService>(EventLogService);
//     await app.init();
//   });

beforeAll(async () => {
  const moduleFixture: TestingModule = await Test.createTestingModule({
    imports: [TestAppModule], // Ensure AppModule provides JwtStrategy and PassportModule
  })
  .overrideProvider(PrismaService)
  .useValue({
    session: {
      findUnique: jest.fn((args: any) => {
        // Your existing session mock logic
        const requestedId = args.where?.id;
        if (requestedId === 'session-id-super') {
          return Promise.resolve({
            id: 'session-id-super',
            csrfToken: 'valid-csrf-token',
            userId: 'super-admin-id',
            tenantId: 'system-tenant',
            revoked: false,
            expiresAt: new Date(Date.now() + 100000),
            ipAddress: '127.0.0.1',
            userAgent: 'test-agent',
            lastActiveAt: new Date(),
            createdAt: new Date(),
            updatedAt: new Date(),
            user: { id: 'super-admin-id', phone: '1234567890', tenantId: 'system-tenant' }
          });
        } else if (requestedId === 'session-id') {
          return Promise.resolve({
            id: 'session-id',
            csrfToken: 'valid-csrf-token',
            userId: 'admin-id',
            tenantId: 'tenant-123',
            revoked: false,
            expiresAt: new Date(Date.now() + 100000),
            ipAddress: '127.0.0.1',
            userAgent: 'test-agent',
            lastActiveAt: new Date(),
            createdAt: new Date(),
            updatedAt: new Date(),
            user: { id: 'admin-id', phone: '1234567890', tenantId: 'tenant-123' }
          });
        } else if (requestedId === 'session-id-user') {
          return Promise.resolve({
            id: 'session-id-user',
            csrfToken: 'valid-csrf-token',
            userId: 'user-id',
            tenantId: 'tenant-456',
            revoked: false,
            expiresAt: new Date(Date.now() + 100000),
            ipAddress: '127.0.0.1',
            userAgent: 'test-agent',
            lastActiveAt: new Date(),
            createdAt: new Date(),
            updatedAt: new Date(),
            user: { id: 'user-id', phone: '1234567890', tenantId: 'tenant-456' }
          });
        }
        return Promise.resolve(null);
      }),
      // ADD THE MISSING findMany METHOD that DeviceFingerprintingService needs
      findMany: jest.fn().mockResolvedValue([]), // This fixes the DeviceFingerprintingService initialization error
    },
    userRole: {
      findMany: jest.fn((args: any) => {
        // Your existing mock
        return Promise.resolve([]);
      }),
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
      update: jest.fn(),
      delete: jest.fn(),
    },
    user: {
      findUnique: jest.fn(),
      findMany: jest.fn(),  // Add this
      count: jest.fn(),    // Add this
      create: jest.fn(),
      update: jest.fn(),
      delete: jest.fn(),
      findFirst: jest.fn(),
    },
    tenantRateLimitProfile: {
      findFirst: jest.fn().mockResolvedValue(null),
      findMany: jest.fn().mockResolvedValue([]),
      create: jest.fn(),
      update: jest.fn(),
      delete: jest.fn(),
    },
    // ADD THE MISSING event model
    event: {
      findMany: jest.fn().mockResolvedValue([]),
      findUnique: jest.fn(),
      findFirst: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
      delete: jest.fn(),
      count: jest.fn(),
    },
    // ADD THE MISSING iPBlock model - fixes the runtime error
    iPBlock: {
      findFirst: jest.fn().mockResolvedValue(null), // Return null if IP not blocked
      findMany: jest.fn().mockResolvedValue([]),
      create: jest.fn(),
      update: jest.fn(),
      delete: jest.fn(),
      upsert: jest.fn(),
    },
    // Add other required methods
    $connect: jest.fn(),
    $disconnect: jest.fn(),

    role: {
      findMany: jest.fn(),
    }
  })
  .overrideProvider(EventLogService) // Mock EventLogService
  .useValue({
    logEvent: jest.fn(),
    queryEvents: jest.fn(), // Might be needed if getAuditEvents is called
    event$: {
      subscribe: jest.fn(() => ({
        unsubscribe: jest.fn(),
      })),
    },
  })
  // ADD MOCKS FOR ALL THE SERVICES FROM YOUR MODULES
  .overrideProvider(IPReputationService)
  .useValue({
    checkIP: jest.fn().mockResolvedValue({ isBlocked: false, confidence: 0.1 }),
    isIPBlocked: jest.fn().mockResolvedValue(false),
    // Add other methods as needed
  })
  .overrideProvider(DeviceFingerprintingService)
  .useValue({
    analyzeFingerprint: jest.fn().mockResolvedValue({ isBot: false, confidence: 0.1 }),
    generateFingerprint: jest.fn().mockResolvedValue('mock-fingerprint'),
    // Add other methods as needed
  })
  .overrideProvider(BotDetectionService)
  .useValue({
    detectBot: jest.fn().mockResolvedValue({ isBot: false, confidence: 0.1 }),
    // Add other methods as needed
  })
  .overrideProvider(BehavioralAnalysisService)
  .useValue({
    analyzeBehavior: jest.fn().mockResolvedValue({ isSuspicious: false, riskScore: 0.1 }),
    // Add other methods as needed
  })
  .overrideProvider(SecurityMonitoringService)
  .useValue({
    logSecurityEvent: jest.fn(),
    checkSecurityStatus: jest.fn().mockResolvedValue({ isSecure: true }),
    // Add other methods as needed
  })
  .overrideProvider(RateLimitingService) // This is the critical one!
  .useValue({
    isRequestAllowed: jest.fn().mockResolvedValue({ allowed: true, resetTime: Date.now() + 1000 }),
    checkRateLimit: jest.fn().mockResolvedValue({ allowed: true, resetTime: Date.now() + 1000 }),
    consumeRateLimit: jest.fn().mockResolvedValue({ allowed: true, resetTime: Date.now() + 1000 }),
    // Add other methods as needed
  })
  .compile();

  app = moduleFixture.createNestApplication();
  // Apply the mockCookieParser middleware before NestJS routes/guards are executed
  // This ensures req.cookies is populated before CsrfGuard runs
  app.use(mockCookieParser);

  prisma = moduleFixture.get<PrismaService>(PrismaService);
  eventLogService = moduleFixture.get<EventLogService>(EventLogService);
  await app.init();
});

  afterAll(async () => {
    await app.close();
  });

  describe('Authentication Guard Tests', () => {
    // For these tests, the real JwtAuthGuard will run.
    // We need to mock Prisma calls inside the real JwtStrategy's validate method
    // to control its outcome (e.g., make it fail for invalid token/session).

    beforeEach(() => {
      // Reset mocks before each test to avoid state carryover
      jest.clearAllMocks();
    });

    it('should return 401 for requests without JWT token', async () => {
      // The real JwtAuthGuard will check for the header and fail if missing.
      const response = await request(app.getHttpServer())
        .get('/v1/admin/users')
        .expect(401); // Should get 401 because no token provided

      expect(response.body).toHaveProperty('message');
    });

    it('should return 401 for requests with invalid JWT token (e.g., session not found)', async () => {
      // Generate a token with a valid signature but an ID that won't be found in the DB
      const payload: JwtPayload = {
        sub: 'user-id',
        sessionId: 'non-existent-session-id', // This ID will be looked up and not found
        tenantId: 'tenant-id',
        csrfToken: 'csrf-token',
        // Optional: set a future expiration to ensure token validity isn't the issue
        exp: Math.floor(Date.now() / 1000) + 3600,
      };
      const token = generateValidJwtToken(payload);

      // Mock the PrismaService call inside JwtStrategy.validate to simulate a failure
      // e.g., session not found.
      (prisma.session.findUnique as jest.MockedFunction<any>).mockResolvedValue(null);

      const response = await request(app.getHttpServer())
        .get('/v1/admin/users')
        .set('Authorization', `Bearer ${token}`)
        .expect(401); // Should get 401 because session lookup failed

      expect(response.body).toHaveProperty('message');
    });

    it('should return 401 for requests with expired JWT token', async () => {
        const expiredSessionId = 'expired-session-id';
        const userId = 'user-id';
        const tenantId = 'tenant-id';
        const csrfToken = 'csrf-token';
        const payload: JwtPayload = {
            sub: userId,
            sessionId: expiredSessionId,
            tenantId: tenantId,
            csrfToken: csrfToken,
            // Expired 2 hours ago
            exp: Math.floor(Date.now() / 1000) - (2 * 60 * 60),
        };

        const token = generateValidJwtToken(payload);

        // Mock the PrismaService call inside JwtStrategy.validate to return an expired session
        (prisma.session.findUnique as jest.MockedFunction<any>).mockResolvedValue({
            id: expiredSessionId,
            userId: userId,
            tenantId: tenantId,
            csrfToken: csrfToken, // Might be needed for subsequent guards
            revoked: false,
            createdAt: new Date(Date.now() - 1000 * 60 * 60 * 25), // Created 25 hours ago
            lastActiveAt: new Date(Date.now() - 1000 * 60 * 60 * 25), // Last active 25 hours ago
            expiresAt: new Date(Date.now() - 1000 * 60 * 60 * 2), // Expired 2 hours ago
            user: { id: userId, tenantId: tenantId } // Include user if JwtStrategy needs it via Prisma
        });

        const response = await request(app.getHttpServer())
            .get('/v1/admin/users')
            .set('Authorization', `Bearer ${token}`) // Use the generated token
            .expect(401); // Should get 401 because session is expired

        expect(response.body).toHaveProperty('message');
    });

    it('should return 401 for requests with revoked JWT token', async () => {
        const revokedSessionId = 'revoked-session-id';
        const userId = 'user-id';
        const tenantId = 'tenant-id';
        const csrfToken = 'csrf-token';
        const payload: JwtPayload = {
            sub: userId,
            sessionId: revokedSessionId,
            tenantId: tenantId,
            csrfToken: csrfToken,
            // Expires in 2 hours
            exp: Math.floor(Date.now() / 1000) + (2 * 60 * 60),
        };

        const token = generateValidJwtToken(payload);

        // Mock the PrismaService call inside JwtStrategy.validate to return a revoked session
        (prisma.session.findUnique as jest.MockedFunction<any>).mockResolvedValue({
            id: revokedSessionId,
            userId: userId,
            tenantId: tenantId,
            csrfToken: csrfToken, // Might be needed for subsequent guards
            revoked: true, // Marked as revoked
            createdAt: new Date(Date.now() - 1000 * 60 * 60), // Created 1 hour ago
            lastActiveAt: new Date(Date.now() - 1000 * 60 * 30), // Last active 30 mins ago
            expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 2), // Expires in 2 hours
            user: { id: userId, tenantId: tenantId } // Include user if JwtStrategy needs it via Prisma
        });

        const response = await request(app.getHttpServer())
            .get('/v1/admin/users')
            .set('Authorization', `Bearer ${token}`) // Use the generated token
            .expect(401); // Should get 401 because session is revoked

        expect(response.body).toHaveProperty('message');
    });
  });

  describe('Role Guard Tests', () => {
    beforeEach(() => {
      // Reset mocks before each test to avoid state carryover
      jest.clearAllMocks();
    });

    // To make the real JwtStrategy pass validation, we need to mock its Prisma dependencies
    // to return data consistent with a valid session.
    // This helper sets up the mock for the session lookup part of JwtStrategy.validate.
    const mockValidJwtSession = (userId: string, tenantId: string, sessionId: string, csrfToken: string = 'valid-csrf-token') => {
      // Mock the PrismaService calls inside JwtStrategy.validate
      (prisma.session.findUnique as jest.MockedFunction<any>).mockResolvedValue({
        id: sessionId,
        userId: userId,
        tenantId: tenantId,
        csrfToken: csrfToken, // Needed for CSRF guard later
        revoked: false,
        createdAt: new Date(),
        lastActiveAt: new Date(),
        expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24), // 24 hours from now
        user: { id: userId, tenantId: tenantId } // Include user if JwtStrategy needs it via Prisma
      });
    };

    it('should reject non-ADMIN/SUPER_ADMIN users with ForbiddenException', async () => {
      const userId = 'user-id';
      const tenantId = 'tenant-id';
      const sessionId = 'valid-session-id';
      const csrfToken = 'valid-csrf-token';
      const payload: JwtPayload = {
          sub: userId,
          sessionId: sessionId,
          tenantId: tenantId,
          csrfToken: csrfToken,
          // Expires in 24 hours
          exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60),
      };

      const token = generateValidJwtToken(payload);

      // Mock successful JWT validation by mocking Prisma calls in JwtStrategy.validate
      mockValidJwtSession(userId, tenantId, sessionId, csrfToken);

      // Mock the PrismaService calls for RoleGuard
      (prisma.user.findUnique as jest.MockedFunction<any>).mockResolvedValue({
        id: userId,
        tenantId: tenantId,
      });
      (prisma.userRole.findMany as jest.MockedFunction<any>).mockResolvedValue([
        {
          userId: userId,
          roleId: 'role-id',
          role: {
            id: 'role-id',
            name: 'USER', // Non-admin role
            tenantId: tenantId,
            isSystem: false,
            isActive: true,
            createdAt: new Date(),
            validFrom: new Date(),
            validUntil: new Date(),
          },
        },
      ]);

      // Mock AdminService's potential call to prisma.user.findMany and prisma.user.count
      (prisma.user.findMany as jest.MockedFunction<any>).mockResolvedValue([]);
      (prisma.user.count as jest.MockedFunction<any>).mockResolvedValue(0);

      const response = await request(app.getHttpServer())
        .get('/v1/admin/users')
        .set('Authorization', `Bearer ${token}`) // Use the generated token
        .set('x-csrf-token', csrfToken) // Needed for CSRF guard
        .set('Cookie', `latch_session=${sessionId}; latch_csrf=${csrfToken}`) // Needed for CSRF guard
        .expect(403); // Should now correctly hit the RoleGuard and get 403

      expect(response.body).toHaveProperty('message');
    });

    it('should allow ADMIN users to access ADMIN endpoints', async () => {
      const userId = 'admin-user-id';
      const tenantId = 'tenant-id';
      const tenantSlug = 'tenant-slug-for-tenant-id';
      const sessionId = 'valid-session-id';
      const csrfToken = 'valid-csrf-token';
      const payload: JwtPayload = {
          sub: userId,
          sessionId: sessionId,
          tenantId: tenantId,
          csrfToken: csrfToken,
          // Expires in 24 hours
          exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60),
      };

      const token = generateValidJwtToken(payload);

      // Mock successful JWT validation
      mockValidJwtSession(userId, tenantId, sessionId, csrfToken);

      // Mock the PrismaService calls for RoleGuard (ADMIN role)
      (prisma.user.findUnique as jest.MockedFunction<any>).mockResolvedValue({
        id: userId,
        tenantId: tenantId,
      });
      (prisma.userRole.findMany as jest.MockedFunction<any>).mockResolvedValue([
        {
          userId: userId,
          roleId: 'admin-role-id',
          role: {
            id: 'admin-role-id',
            name: 'ADMIN',
            tenantId: tenantId,
            isSystem: false,
            isActive: true,
            createdAt: new Date(),
            validFrom: new Date(),
            validUntil: new Date(),
          },
        },
      ]);

        // Mock Tenant lookup for TenantGuard based on the SLUG provided in the header
  // This mock should return a tenant object where the 'id' matches the user's tenantId ('tenant-id')
  // to allow the tenant isolation check to pass.
  (prisma.tenant.findUnique as jest.MockedFunction<any>).mockResolvedValue({
    id: tenantId, // Matches the user's tenantId from the token
    name: 'Test Tenant',
    slug: tenantSlug, // The slug that matches the header value
    status: 'ACTIVE',
    createdAt: new Date(),
    updatedAt: new Date(),
  });

      // Mock AdminService's calls to prisma.user.findMany and prisma.user.count
      const mockUsers = [{ id: 'user1', name: 'User One', email: 'user1@example.com', tenantId, roles: [] }];
      (prisma.user.findMany as jest.MockedFunction<any>).mockResolvedValue(mockUsers);
      (prisma.user.count as jest.MockedFunction<any>).mockResolvedValue(mockUsers.length);

      const response = await request(app.getHttpServer())
        .get('/v1/admin/users')
        .set('Authorization', `Bearer ${token}`) // Use the generated token
        .set('x-csrf-token', csrfToken) // Needed for CSRF guard
        .set('x-tenant-slug', tenantSlug)
        .set('Cookie', `latch_session=${sessionId}; latch_csrf=${csrfToken}`) // Needed for CSRF guard
        .expect(200); // Should now pass all guards and get users data

      expect(response.body).toHaveProperty('data');
      expect(response.body).toHaveProperty('meta');
    });

    it('should allow SUPER_ADMIN users to access ADMIN endpoints', async () => {
      const userId = 'super-admin-user-id';
      const tenantId = 'tenant-id';
      const tenantSlug = 'tenant-slug-for-tenant-id';
      const sessionId = 'valid-session-id';
      const csrfToken = 'valid-csrf-token';
      const payload: JwtPayload = {
          sub: userId,
          sessionId: sessionId,
          tenantId: tenantId,
          csrfToken: csrfToken,
          // Expires in 24 hours
          exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60),
      };

      const token = generateValidJwtToken(payload);

      // Mock successful JWT validation
      mockValidJwtSession(userId, tenantId, sessionId, csrfToken);

      // Mock the PrismaService calls for RoleGuard (SUPER_ADMIN role)
      (prisma.user.findUnique as jest.MockedFunction<any>).mockResolvedValue({
        id: userId,
        tenantId: tenantId,
      });
      (prisma.userRole.findMany as jest.MockedFunction<any>).mockResolvedValue([
        {
          userId: userId,
          roleId: 'super-admin-role-id',
          role: {
            id: 'super-admin-role-id',
            name: 'SUPER_ADMIN',
            tenantId: tenantId,
            isSystem: false,
            isActive: true,
            createdAt: new Date(),
            validFrom: new Date(),
            validUntil: new Date(),
          },
        },
      ]);

      (prisma.tenant.findUnique as jest.MockedFunction<any>).mockResolvedValue({
        id: tenantId, // Matches the user's tenantId from the token
        name: 'Test Tenant',
        slug: tenantSlug, // The slug that matches the header value
        status: 'ACTIVE',
        createdAt: new Date(),
        updatedAt: new Date(),
      });
      
      // Mock AdminService's calls to prisma.user.findMany and prisma.user.count
      const mockUsers = [{ id: 'user2', name: 'User Two', email: 'user2@example.com', tenantId, roles: [] }];
      (prisma.user.findMany as jest.MockedFunction<any>).mockResolvedValue(mockUsers);
      (prisma.user.count as jest.MockedFunction<any>).mockResolvedValue(mockUsers.length);

      const response = await request(app.getHttpServer())
        .get('/v1/admin/users')
        .set('Authorization', `Bearer ${token}`) // Use the generated token
        .set('x-csrf-token', csrfToken) // Needed for CSRF guard
        .set('x-tenant-slug', tenantSlug)
        .set('Cookie', `latch_session=${sessionId}; latch_csrf=${csrfToken}`)// Needed for CSRF guard
        .expect(200); // Should now pass all guards

      expect(response.body).toHaveProperty('data');
      expect(response.body).toHaveProperty('meta');
    });
  });

  describe('CSRF Guard Tests', () => {
    beforeEach(() => {
      // Reset mocks before each test
      jest.clearAllMocks();
    });

    const mockValidJwtSession = (userId: string, tenantId: string, sessionId: string, csrfToken: string) => {
      // Mock the PrismaService calls inside JwtStrategy.validate
      (prisma.session.findUnique as jest.MockedFunction<any>).mockResolvedValue({
        id: sessionId,
        userId: userId,
        tenantId: tenantId,
        csrfToken: csrfToken, // Use the provided CSRF token
        revoked: false,
        createdAt: new Date(),
        lastActiveAt: new Date(),
        expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24),
        user: { id: userId, tenantId: tenantId }
      });
    };

    // Helper for Role Guard setup
    const mockAdminRole = (userId: string, tenantId: string) => {
        (prisma.user.findUnique as jest.MockedFunction<any>).mockResolvedValue({
            id: userId,
            tenantId: tenantId,
        });
        (prisma.userRole.findMany as jest.MockedFunction<any>).mockResolvedValue([
            {
            userId: userId,
            roleId: 'admin-role-id',
            role: {
                id: 'admin-role-id',
                name: 'ADMIN',
                tenantId: tenantId,
                isSystem: false,
                isActive: true,
                createdAt: new Date(),
                validFrom: new Date(),
                validUntil: new Date(),
            },
            },
        ]);
    };

    it('should reject requests without CSRF token', async () => {
        const userId = 'admin-user-id';
        const tenantId = 'tenant-id';
        const sessionId = 'valid-session-id';
        const csrfToken = 'valid-csrf-token';
        const payload: JwtPayload = {
            sub: userId,
            sessionId: sessionId,
            tenantId: tenantId,
            csrfToken: csrfToken,
            // Expires in 24 hours
            exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60),
        };

        const token = generateValidJwtToken(payload);

        // Mock successful JWT validation
        mockValidJwtSession(userId, tenantId, sessionId, csrfToken);
        // Mock Role Guard
        mockAdminRole(userId, tenantId);

        // Mock AdminService's potential call to prisma.user.findMany and prisma.user.count
        (prisma.user.findMany as jest.MockedFunction<any>).mockResolvedValue([]);
        (prisma.user.count as jest.MockedFunction<any>).mockResolvedValue(0);

        const response = await request(app.getHttpServer())
        .get('/v1/admin/users')
        .set('Authorization', `Bearer ${token}`) // Use the generated token
        .set('Cookie', `latch_session=${sessionId}; latch_csrf=${csrfToken}`) // Cookie has the token
        // Deliberately omit 'x-csrf-token' header
        .expect(403); // Should fail CSRF guard

        expect(response.body).toHaveProperty('message');
    });

    it('should reject requests with mismatched CSRF tokens', async () => {
        const userId = 'admin-user-id';
        const tenantId = 'tenant-id';
        const sessionId = 'valid-session-id';
        const sessionCsrfToken = 'session-csrf-token';
        const requestCsrfToken = 'request-csrf-token';
        const payload: JwtPayload = {
            sub: userId,
            sessionId: sessionId,
            tenantId: tenantId,
            csrfToken: sessionCsrfToken, // CSRF token stored in the session
            // Expires in 24 hours
            exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60),
        };

        const token = generateValidJwtToken(payload);

        // Mock successful JWT validation with a specific CSRF token in the session
        mockValidJwtSession(userId, tenantId, sessionId, sessionCsrfToken);
        // Mock Role Guard
        mockAdminRole(userId, tenantId);

        // Mock AdminService's potential call to prisma.user.findMany and prisma.user.count
        (prisma.user.findMany as jest.MockedFunction<any>).mockResolvedValue([]);
        (prisma.user.count as jest.MockedFunction<any>).mockResolvedValue(0);

        const response = await request(app.getHttpServer())
        .get('/v1/admin/users')
        .set('Authorization', `Bearer ${token}`) // Use the generated token
        .set('x-csrf-token', requestCsrfToken) // Send different token
        .set('Cookie', `latch_session=${sessionId}; latch_csrf=${sessionCsrfToken}`) // Cookie has the session token
        .expect(403); // Should fail CSRF guard due to mismatch

        expect(response.body).toHaveProperty('message');
    });

    it('should allow requests with valid CSRF tokens', async () => {
        const userId = 'admin-user-id';
        const tenantId = 'tenant-id';
        const sessionId = 'valid-session-id';
        const tenantSlug = 'tenant-slug-for-tenant-id';
        const csrfToken = 'valid-csrf-token';
        const payload: JwtPayload = {
            sub: userId,
            sessionId: sessionId,
            tenantId: tenantId,
            csrfToken: csrfToken,
            // Expires in 24 hours
            exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60),
        };

        const token = generateValidJwtToken(payload);

        // Mock successful JWT validation
        mockValidJwtSession(userId, tenantId, sessionId, csrfToken);
        // Mock Role Guard
        mockAdminRole(userId, tenantId);

(prisma.tenant.findUnique as jest.MockedFunction<any>).mockResolvedValue({
    id: tenantId, // Matches the user's tenantId from the token
    name: 'Test Tenant',
    slug: tenantSlug, // The slug that matches the header value
    status: 'ACTIVE',
    createdAt: new Date(),
    updatedAt: new Date(),
  });

        // Mock AdminService's calls to prisma.user.findMany and prisma.user.count
        const mockUsers = [{ id: 'user3', name: 'User Three', email: 'user3@example.com', tenantId, roles: [] }];
        (prisma.user.findMany as jest.MockedFunction<any>).mockResolvedValue(mockUsers);
        (prisma.user.count as jest.MockedFunction<any>).mockResolvedValue(mockUsers.length);

        const response = await request(app.getHttpServer())
        .get('/v1/admin/users')
        .set('Authorization', `Bearer ${token}`) // Use the generated token
        .set('x-csrf-token', csrfToken) // Send matching token
        .set('x-tenant-slug', tenantSlug) 
        .set('Cookie', `latch_session=${sessionId}; latch_csrf=${csrfToken}`) // Cookie has the token
        .expect(200); // Should pass all guards

        expect(response.body).toHaveProperty('data');
        expect(response.body).toHaveProperty('meta');
    });
  });

  describe('Tenant Guard Tests', () => {
    beforeEach(() => {
      // Reset mocks before each test
      jest.clearAllMocks();
    });

    const mockValidJwtSession = (userId: string, tenantId: string, sessionId: string, csrfToken: string = 'valid-csrf-token') => {
      // Mock the PrismaService calls inside JwtStrategy.validate
      (prisma.session.findUnique as jest.MockedFunction<any>).mockResolvedValue({
        id: sessionId,
        userId: userId,
        tenantId: tenantId,
        csrfToken: csrfToken,
        revoked: false,
        createdAt: new Date(),
        lastActiveAt: new Date(),
        expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24),
        user: { id: userId, tenantId: tenantId }
      });
    };

    const mockAdminRole = (userId: string, tenantId: string) => {
        (prisma.user.findUnique as jest.MockedFunction<any>).mockResolvedValue({
            id: userId,
            tenantId: tenantId,
        });
        (prisma.userRole.findMany as jest.MockedFunction<any>).mockResolvedValue([
            {
            userId: userId,
            roleId: 'admin-role-id',
            role: {
                id: 'admin-role-id',
                name: 'ADMIN',
                tenantId: tenantId,
                isSystem: false,
                isActive: true,
                createdAt: new Date(),
                validFrom: new Date(),
                validUntil: new Date(),
            },
            },
        ]);
    };

    it('should reject requests with invalid tenant slug format', async () => {
        const userId = 'admin-user-id';
        const tokenTenantId = 'token-tenant-id'; // Tenant from JWT payload (via mock session/user)
        const sessionId = 'valid-session-id';
        const csrfToken = 'valid-csrf-token';
        const payload: JwtPayload = {
            sub: userId,
            sessionId: sessionId,
            tenantId: tokenTenantId,
            csrfToken: csrfToken,
            // Expires in 24 hours
            exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60),
        };

        const token = generateValidJwtToken(payload);

        // Mock successful JWT validation for a specific tenant (tokenTenantId)
        mockValidJwtSession(userId, tokenTenantId, sessionId, csrfToken);
        // Mock Role Guard using the token's tenant ID
        mockAdminRole(userId, tokenTenantId);

        // Mock AdminService's potential call to prisma.user.findMany and prisma.user.count
        // Even if the endpoint fails before reaching the controller logic,
        // it's safer to mock these to prevent the 500 error if the endpoint *is* hit.
        (prisma.user.findMany as jest.MockedFunction<any>).mockResolvedValue([]);
        (prisma.user.count as jest.MockedFunction<any>).mockResolvedValue(0);

        const response = await request(app.getHttpServer())
        .get('/v1/admin/users')
        .set('Authorization', `Bearer ${token}`) // Use the generated token
        .set('x-csrf-token', csrfToken) // Needed for CSRF guard
        .set('x-tenant-slug', 'invalid@tenant') // Invalid format, should fail before DB check
        .set('Cookie', `latch_session=${sessionId}; latch_csrf=${csrfToken}`) // Needed for CSRF guard
        .expect(400); // Expect 400 for invalid format

        expect(response.body).toHaveProperty('message');
    });

    it('should reject requests with non-existent tenant', async () => {
        const userId = 'admin-user-id';
        const tokenTenantId = 'token-tenant-id'; // Tenant from JWT (via mock)
        const requestTenantSlug = 'non-existent-tenant';
        const sessionId = 'valid-session-id';
        const csrfToken = 'valid-csrf-token';
        const payload: JwtPayload = {
            sub: userId,
            sessionId: sessionId,
            tenantId: tokenTenantId,
            csrfToken: csrfToken,
            // Expires in 24 hours
            exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60),
        };

        const token = generateValidJwtToken(payload);

        // Mock successful JWT validation for a specific tenant (tokenTenantId)
        mockValidJwtSession(userId, tokenTenantId, sessionId, csrfToken);
        // Mock Role Guard using the token's tenant ID
        mockAdminRole(userId, tokenTenantId);
        // Mock tenant lookup to return null (not found)
        (prisma.tenant.findUnique as jest.MockedFunction<any>).mockResolvedValue(null);

        // Mock AdminService's potential call to prisma.user.findMany and prisma.user.count
        (prisma.user.findMany as jest.MockedFunction<any>).mockResolvedValue([]);
        (prisma.user.count as jest.MockedFunction<any>).mockResolvedValue(0);

        const response = await request(app.getHttpServer())
        .get('/v1/admin/users')
        .set('Authorization', `Bearer ${token}`) // Use the generated token
        .set('x-csrf-token', csrfToken) // Needed for CSRF guard
        .set('x-tenant-slug', requestTenantSlug) // Requesting different tenant
        .set('Cookie', `latch_session=${sessionId}; latch_csrf=${csrfToken}`) // Needed for CSRF guard
        .expect(403); // Should fail Tenant guard because tenant doesn't exist

        expect(response.body).toHaveProperty('message');
    });

    it('should reject requests with tenant mismatch', async () => {
        const userId = 'admin-user-id';
        const tokenTenantId = 'token-tenant-id'; // Tenant from JWT (via mock session/user)
        const requestTenantSlug = 'request-tenant-slug'; // Slug from header/param
        const sessionId = 'valid-session-id';
        const csrfToken = 'valid-csrf-token';
        const payload: JwtPayload = {
            sub: userId,
            sessionId: sessionId,
            tenantId: tokenTenantId,
            csrfToken: csrfToken,
            // Expires in 24 hours
            exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60),
        };

        const token = generateValidJwtToken(payload);

        // Mock successful JWT validation for a specific tenant (tokenTenantId)
        mockValidJwtSession(userId, tokenTenantId, sessionId, csrfToken);
        // Mock Role Guard using the token's tenant ID
        mockAdminRole(userId, tokenTenantId);
        // Mock tenant lookup for the *requested* slug to return a different tenant
        (prisma.tenant.findUnique as jest.MockedFunction<any>).mockResolvedValue({
            id: 'different-target-tenant-id',
            name: 'Target Tenant',
            slug: requestTenantSlug,
            status: 'ACTIVE',
            createdAt: new Date(),
            updatedAt: new Date(),
        });

        // Mock AdminService's potential call to prisma.user.findMany and prisma.user.count
        (prisma.user.findMany as jest.MockedFunction<any>).mockResolvedValue([]);
        (prisma.user.count as jest.MockedFunction<any>).mockResolvedValue(0);

        const response = await request(app.getHttpServer())
        .get('/v1/admin/users')
        .set('Authorization', `Bearer ${token}`) // Use the generated token
        .set('x-csrf-token', csrfToken) // Needed for CSRF guard
        .set('x-tenant-slug', requestTenantSlug) // Requesting different tenant
        .set('Cookie', `latch_session=${sessionId}; latch_csrf=${csrfToken}`) // Needed for CSRF guard
        .expect(403); // Should fail Tenant guard due to mismatch

        expect(response.body).toHaveProperty('message');
    });
  });
});