import * as dotenv from 'dotenv';
dotenv.config({ path: '.env.test' });

import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { App } from 'supertest/types';
import { AppModule } from './../src/app.module';

describe('AppController (e2e)', () => {
  let app: INestApplication<App>;

  beforeEach(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.setGlobalPrefix('v1');
    await app.init();
  });

  // Test the health endpoint instead of root
  it('/v1/health (GET)', () => {
    return request(app.getHttpServer())
      .get('/v1/health')  // Test an endpoint that exists
      .expect(200);
  });

  // Or if you want to test root, check what's available
  it('/ (GET) should return 404 or redirect', () => {
    return request(app.getHttpServer())
      .get('/v1')
      .expect(404); // If no root route is defined, 404 is correct
  });
  afterAll(async () => {
    await app.close();
    });
});

