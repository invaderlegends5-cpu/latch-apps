// src/auth/auth.module.ts
import { Module, forwardRef } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule } from '@nestjs/config';
import { APP_INTERCEPTOR } from '@nestjs/core';
import { JwtModule } from '@nestjs/jwt';
import { EventsModule } from '../events/events.module';
import { AuthService } from './auth.service';
import { JwtStrategy } from './jwt.strategy';
import { NormalizeRequestInterceptor } from './interceptors/normalize-request.interceptor';
import { AuthController } from './auth.controller';
import { CsrfGuard } from './guards/csrf.guard';
import { PrismaService } from '../prisma/prisma.service';
import { EventLogService } from 'src/events/event.service';
import { SessionGuard } from './guards/session.guard';

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.register({
      secret: process.env.JWT_SECRET ?? 'dev_jwt_secret_change_me',
      signOptions: { expiresIn: '15m' },
    }),
    // EventsModule,
    forwardRef(() => EventsModule),
    ConfigModule,
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    PrismaService,
    JwtStrategy,
    CsrfGuard,
    EventLogService,
    SessionGuard,
    // ✅ Register the interceptor here
    {
      provide: APP_INTERCEPTOR,
      useClass: NormalizeRequestInterceptor,
    },
  ],
  exports: [AuthService],
})
export class AuthModule {}
