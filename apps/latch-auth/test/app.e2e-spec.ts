import * as dotenv from 'dotenv';
dotenv.config({ path: '.env.test' });

import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { AppModule } from './../src/app.module';
import { IPReputationService } from '@/ip-reputation/ip-reputation.service';

// Import your actual Redis service class
import { RedisService } from './../src/redis/redis.service'; // Adjust path as needed

describe('AppController (e2e)', () => {
  let app: INestApplication;

  beforeEach(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    })
    .overrideProvider(IPReputationService)
    .useValue({
      isIPBlocked: jest.fn().mockResolvedValue(false),
      calculateReputation: jest.fn().mockResolvedValue({ score: 0, isBot: false, recommendation: 'ALLOW' }),
      updateReputation: jest.fn().mockResolvedValue(undefined),
      isValidIP: jest.fn().mockReturnValue(true), 
    })
    .overrideProvider(RedisService) // Use the actual class, not a string
    .useValue({
      setex: jest.fn().mockResolvedValue('OK'),
      get: jest.fn().mockResolvedValue(null),
      del: jest.fn().mockResolvedValue(1),
      set: jest.fn().mockResolvedValue('OK'),
      connect: jest.fn().mockResolvedValue(undefined),
      on: jest.fn(), 
      quit: jest.fn().mockResolvedValue(undefined),
      // Add any other methods your app calls on the Redis service
    })
    .compile();

    app = moduleRef.createNestApplication();
    app.setGlobalPrefix('v1');
    await app.init();
  });

  afterEach(async () => {
    await app.close();
  });

  it('/v1/health (GET)', () => {
    return request(app.getHttpServer())
      .get('/v1/health')
      .expect(200);
  });

  // it('/ (GET)', () => {
  //   return request(app.getHttpServer())
  //     .get('/')
  //     .expect(200)
  //     .expect('Hello World!');
  // });
});