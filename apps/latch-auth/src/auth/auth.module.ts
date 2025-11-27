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
import { EventLogService } from '../events/event.service';
import { SessionGuard } from './guards/session.guard';
import { IPReputationService } from '@/ip-reputation/ip-reputation.service';
import { DeviceFingerprintingService } from '@/device-fingerprinting/device-fingerprinting.service';
import { BehavioralAnalysisService } from '@/behavioral-analysis/behavioral-analysis.service';
import { BotDetectionService } from '@/bot-detection/bot-detection.service';
import { SecurityMonitoringService } from '@/security/security-monitor.service';
import { RateLimitingService } from '@/rate-limiting/rate-limiting.service';

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
    IPReputationService,
    DeviceFingerprintingService,
    BehavioralAnalysisService,
    BotDetectionService,
    SecurityMonitoringService,
    RateLimitingService,
    // ✅ Register the interceptor here
    {
      provide: APP_INTERCEPTOR,
      useClass: NormalizeRequestInterceptor,
    },
  ],
  exports: [AuthService],
})
export class AuthModule {}
