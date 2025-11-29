// test/auth/logout.e2e-spec.ts
import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { AppModule } from '../../src/app.module';
import { DevOtpStore } from '../../src/utils/dev-otp-store';
import { PrismaService } from '../../src/prisma/prisma.service';
import cookieParser from 'cookie-parser';
import { IPReputationService } from '@/ip-reputation/ip-reputation.service';

describe('Auth Lifecycle (E2E)', () => {
  let app: INestApplication;
  let prisma: PrismaService;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    })
    .overrideProvider(IPReputationService)
    .useValue({
        // Mock the isIPBlocked method to return false and prevent validation errors
        isIPBlocked: jest.fn().mockResolvedValue(false),
        // Mock any other methods the tests trigger
        calculateReputation: jest.fn().mockResolvedValue({ score: 0, isBot: false, recommendation: 'ALLOW' }),
        updateReputation: jest.fn().mockResolvedValue(undefined),
        // Add isValidIP if it's public and called directly by other services
        isValidIP: jest.fn().mockReturnValue(true), 
    }).compile();

    app = moduleRef.createNestApplication();
    app.setGlobalPrefix('v1');

    app.enableCors(); // (Optional, if you use CORS)
    const expressApp = app.getHttpAdapter().getInstance();
    expressApp.set('trust proxy', true);

    app.use(cookieParser(process.env.COOKIE_SECRET ?? 'dev_cookie_secret'));
    await app.init();

    prisma = moduleRef.get(PrismaService);
  });

  afterAll(async () => {
    await app.close();
  });

  it('should complete OTP -> verify -> logout flow correctly', async () => {
    const phone = `+1555123456${Date.now()}`;
    const tenantSlug = 'default';

    // 1. Request OTP
    const requestRes = await request(app.getHttpServer())
      .post('/v1/auth/request-otp')
      .send({ phone, tenantSlug })
      .set('x-forwarded-for', '127.0.0.1')
      .set('user-agent', 'jest-e2e-test')
      .expect(201);

    // 2. Get OTP from dev store
    const devOtp = DevOtpStore.get(phone);
    expect(devOtp).toBeDefined();

    // 3. Verify OTP
    const verifyRes = await request(app.getHttpServer())
      .post('/v1/auth/otpVerify')
      .send({ phone, code: devOtp, tenantSlug })
      .set('x-forwarded-for', '127.0.0.1')
      .set('user-agent', 'jest-e2e-test')
      .expect(201);

    // Validate session was created correctly
    const sessionInDb = await prisma.session.findFirst({
      where: { userId: verifyRes.body.user.id },
      orderBy: { createdAt: 'desc' },
    });
    expect(sessionInDb).toBeTruthy();
    expect(sessionInDb!.csrfToken).toBe(verifyRes.body.csrfToken);

    // 4. Extract cookies for logout
    const cookies = verifyRes.headers['set-cookie'];
    const cookieHeader = (Array.isArray(cookies) ? cookies : [cookies])
      .map(c => c.split(';')[0])
      .join('; ');

    // 5. Logout with all required context
    const logoutRes = await request(app.getHttpServer())
      .post('/v1/auth/logout')
      .set('Cookie', cookieHeader)           // 👈 Critical: send cookies manually
      .set('x-tenant-slug', tenantSlug)      // 👈 Required by TenantGuard
      .set('x-csrf-token', verifyRes.body.csrfToken) // 👈 Required by CsrfGuard
      .set('x-forwarded-for', '127.0.0.1')
      .set('user-agent', 'jest-e2e-test')
      .expect(201);

    expect(logoutRes.body).toEqual({ ok: true });
  });

  it('should handle invalid OTP codes', async () => {
    const phone = `+1555123457${Date.now()}`;
    const tenantSlug = 'default';

    await request(app.getHttpServer())
      .post('/v1/auth/request-otp')
      .send({ phone, tenantSlug })
      .set('x-forwarded-for', '127.0.0.1')
      .set('user-agent', 'jest-e2e-test')
      .expect(201);

    const verifyRes = await request(app.getHttpServer())
      .post('/v1/auth/otpVerify')
      .send({ phone, code: '000000', tenantSlug })
      .set('x-forwarded-for', '127.0.0.1')
      .set('user-agent', 'jest-e2e-test');

    expect(verifyRes.status).toBe(401);
  });
});
