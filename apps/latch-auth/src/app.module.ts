// src/app.module.ts
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { ThrottlerModule } from '@nestjs/throttler';
import { ScheduleModule } from '@nestjs/schedule';
import { PrismaService } from './prisma/prisma.service';
import { RedisModule } from './redis/redis.module';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { ProtectedModule } from './protected/protected.module';
import { EventLogService } from './events/event.service';
import { EventsModule } from './events/events.module';
import { SecurityModule } from './security/security.module';
import { HealthModule } from './health/health.module';
import { AppService } from './app.service';
import { TenantsModule } from './tenants/tenants.module';
import { AdminModule } from './admin/admin.module';
import { IPReputationModule } from './ip-reputation/ip-reputation.module';
import { DeviceFingerprintingModule } from './device-fingerprinting/device-fingerprinting.module';
import { BehavioralAnalysisModule } from './behavioral-analysis/behavioral-analysis.module';
import { RateLimitingModule } from './rate-limiting/rate-limiting.module';
import { BotDetectionModule } from './bot-detection/bot-detection.module';
@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    SecurityModule,
    IPReputationModule,
    DeviceFingerprintingModule,
    BehavioralAnalysisModule,
    RateLimitingModule,
    BotDetectionModule,
    ThrottlerModule.forRoot([
      {
        name: 'otpRequest', // 👈 named throttler
        ttl: 300, // 5 minutes
        limit: 3,
      },
      {
        name: 'otpVerify', // 👈 named throttler
        ttl: 600, // 10 minutes
        limit: 6,
      },
      {
        name: 'refresh', // 👈 named throttler
        ttl: 60, // 1 minute
        limit: 20,
      },
      {
        name: 'default', // fallback global
        ttl: 60,
        limit: 100,
      },
    ]),
    ScheduleModule.forRoot(),
    AuthModule,
    UsersModule,
    ProtectedModule,
    EventsModule,
    HealthModule,
    RedisModule,
    TenantsModule,
    AdminModule,
  ],
   providers: [PrismaService,
    AppService,
    //  EventLogService
    ],
})
export class AppModule {}
