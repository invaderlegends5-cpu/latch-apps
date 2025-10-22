import request from 'supertest';
import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { AppModule } from '../../src/app.module';

describe('Auth Lifecycle (E2E)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleRef.createNestApplication();

    // ✅ Apply same global prefix as in main.ts
    app.setGlobalPrefix('v1');

    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  it('should complete OTP -> verify -> logout flow correctly', async () => {
    const otpRes = await request(app.getHttpServer())
      .post('/v1/auth/request-otp')
      .send({ phone: '+15551234567' });

    expect(otpRes.status).toBe(201);
    expect(otpRes.body).toHaveProperty('ok', true);

    const verifyRes = await request(app.getHttpServer())
      .post('/v1/auth/otpVerify')
      .send({
        phone: '+15551234567',
        code: '123456',
      });

    expect(verifyRes.status).toBe(201);
    const cookies = verifyRes.get('Set-Cookie');
    expect(cookies).toEqual(
      expect.arrayContaining([
        expect.stringContaining('latch_refresh='),
        expect.stringContaining('latch_session='),
        expect.stringContaining('latch_csrf='),
      ]),
    );

    const cookieHeader = cookies.map((c: string) => c.split(';')[0]).join('; ');

    const logoutRes = await request(app.getHttpServer())
      .post('/v1/auth/logout')
      .set('Cookie', cookieHeader);

    expect([200, 201]).toContain(logoutRes.status);
    const logoutCookies = logoutRes.get('Set-Cookie');

    for (const c of logoutCookies) {
      expect(c).toContain('Expires=Thu, 01 Jan 1970');
    }
  });
});
