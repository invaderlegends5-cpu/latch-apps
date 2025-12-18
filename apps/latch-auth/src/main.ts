// src/main.ts
import helmet from 'helmet';
import { NestFactory } from '@nestjs/core';
import * as Sentry from '@sentry/node';
import { AppModule } from './app.module';
import cookieParser from 'cookie-parser';
import { ValidationPipe } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { CacheControlInterceptor } from './interceptors/cache-control.interceptor';
import { ClearCookiesExceptionFilter } from './auth/filters/clear-cookies-exception.filter';
import 'tsconfig-paths/register';
Sentry.init({
  dsn: process.env.SENTRY_DSN,
  tracesSampleRate: 0.1,
});

async function waitForDatabase() {
  const prisma = new PrismaClient();
  const maxAttempts = 30;
  let attempts = 0;

  while (attempts < maxAttempts) {
    try {
      await prisma.$connect();
      console.log('✅ Connected to database');
      await prisma.$disconnect();
      return;
    } catch (error) {
      attempts++;
      console.log(`⏳ Waiting for database... (${attempts}/${maxAttempts})`);
      if (attempts === maxAttempts) {
        console.error('❌ Failed to connect to database:', error);
        throw error;
      }
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
  }
}

async function bootstrap() {
  await waitForDatabase();
  const app = await NestFactory.create(AppModule);

  app.use(cookieParser(process.env.COOKIE_SECRET ?? 'dev_cookie_secret'));
  const frontendOrigin = process.env.FRONTEND_ORIGIN || 'http://localhost:5173';

  app.use(
    helmet({
      contentSecurityPolicy:
        process.env.NODE_ENV === 'production'
          ? {
              directives: {
                defaultSrc: ["'self'"],
                scriptSrc: ["'self'", "'unsafe-inline'"],
                styleSrc: ["'self'", "'unsafe-inline'"],
                imgSrc: ["'self'", 'data:'],
                connectSrc: ["'self'", frontendOrigin],
              },
            }
          : false,
    }),
  );

  if (process.env.NODE_ENV === 'production') {
    app.use(
      helmet.hsts({
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true,
      }),
    );
  }

  app.useGlobalInterceptors(new CacheControlInterceptor());
  app.useGlobalPipes(new ValidationPipe({ whitelist: true, transform: true }));

  app.enableCors({
    origin: process.env.FRONTEND_ORIGIN ?? 'http://localhost:5173',
    credentials: true,
  });

  app.setGlobalPrefix('v1');

  // ✅ Enable NestJS shutdown hooks (handles SIGTERM/SIGINT properly)
  app.enableShutdownHooks();

  app.useGlobalFilters(new ClearCookiesExceptionFilter());

  const port = process.env.PORT ? Number(process.env.PORT) : 3000;
  await app.listen(port, '127.0.0.1'); // Listen specifically on IPv4 loopback
  console.log(`Latch API running on http://127.0.0.1:${port}`);
}

void bootstrap();
