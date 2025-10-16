// //src/main.ts
// import helmet from 'helmet';
// import { NestFactory } from '@nestjs/core';
// import * as Sentry from '@sentry/node';
// import { AppModule } from './app.module';
// import cookieParser from 'cookie-parser';
// import { ValidationPipe } from '@nestjs/common';
// import { PrismaService } from './prisma/prisma.service';
// import { CacheControlInterceptor } from './interceptors/cache-control.interceptor';
// import { ClearCookiesExceptionFilter } from './auth/filters/clear-cookies-exception.filter';

// Sentry.init({
//   dsn: process.env.SENTRY_DSN,
//   tracesSampleRate: 0.1,
// });

// async function bootstrap() {
//   const app = await NestFactory.create(AppModule);

//   // Add cookie parser
//   app.use(cookieParser(process.env.COOKIE_SECRET ?? 'dev_cookie_secret'));
//   const frontendOrigin = process.env.FRONTEND_ORIGIN || 'http://localhost:5173';
//   // Helmet with sensible defaults, add HSTS for production
//   app.use(
//     helmet({
//       contentSecurityPolicy:
//         process.env.NODE_ENV === 'production'
//           ? {
//               directives: {
//                 defaultSrc: ["'self'"],
//                 scriptSrc: ["'self'", "'unsafe-inline'"], // revisit for strict CSP
//                 styleSrc: ["'self'", "'unsafe-inline'"],
//                 imgSrc: ["'self'", 'data:'],
//                 connectSrc: ["'self'", frontendOrigin],
//               },
//             }
//           : false,
//     }),
//   );

//   if (process.env.NODE_ENV === 'production') {
//     app.use(
//       helmet.hsts({
//         maxAge: 31536000, // 1 year
//         includeSubDomains: true,
//         preload: true,
//       }),
//     );
//   }

//   // Global interceptors & pipes
//   app.useGlobalInterceptors(new CacheControlInterceptor());
//   app.useGlobalPipes(new ValidationPipe({ whitelist: true }));
//   // Enable CORS
//   app.enableCors({
//     origin: process.env.FRONTEND_ORIGIN ?? 'http://localhost:5173',
//     credentials: true,
//   });

//   app.setGlobalPrefix('v1');

//   // Keep Prisma shutdown hooks
//   const prismaService = app.get(PrismaService);
//   await prismaService.enableShutdownHooks(app);
//   app.useGlobalFilters(new ClearCookiesExceptionFilter());
//   await app.listen(process.env.PORT ? Number(process.env.PORT) : 3000);
//   console.log(`Latch API running on ${await app.getUrl()}`);
// }
// void bootstrap();

// src/main.ts
import helmet from 'helmet';
import { NestFactory } from '@nestjs/core';
import * as Sentry from '@sentry/node';
import { AppModule } from './app.module';
import cookieParser from 'cookie-parser';
import { ValidationPipe } from '@nestjs/common';
// ❌ Remove: PrismaService import (no longer needed here)
import { CacheControlInterceptor } from './interceptors/cache-control.interceptor';
import { ClearCookiesExceptionFilter } from './auth/filters/clear-cookies-exception.filter';

Sentry.init({
  dsn: process.env.SENTRY_DSN,
  tracesSampleRate: 0.1,
});

async function bootstrap() {
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
  app.useGlobalPipes(new ValidationPipe({ whitelist: true }));

  app.enableCors({
    origin: process.env.FRONTEND_ORIGIN ?? 'http://localhost:5173',
    credentials: true,
  });

  app.setGlobalPrefix('v1');

  // ✅ Enable NestJS shutdown hooks (handles SIGTERM/SIGINT properly)
  app.enableShutdownHooks();

  app.useGlobalFilters(new ClearCookiesExceptionFilter());

  await app.listen(process.env.PORT ? Number(process.env.PORT) : 3000);
  console.log(`Latch API running on ${await app.getUrl()}`);
}

void bootstrap();
