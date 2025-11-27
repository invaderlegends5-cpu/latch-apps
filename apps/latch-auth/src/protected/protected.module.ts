// src/protected/protected.module.ts
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { ProtectedController } from './protected.controller';
import { PrismaService } from '../prisma/prisma.service';
import { EventLogService } from '../events/event.service';
import { SessionGuard } from '../auth/guards/session.guard';
import { AuthModule } from '../auth/auth.module';
import { IPReputationService } from '@/ip-reputation/ip-reputation.service';
import { BehavioralAnalysisModule } from '@/behavioral-analysis/behavioral-analysis.module';
import { DeviceFingerprintingModule } from '@/device-fingerprinting/device-fingerprinting.module';
import { SecurityModule } from '@/security/security.module';
import { BotDetectionService } from '@/bot-detection/bot-detection.service';
import { RateLimitingService } from '@/rate-limiting/rate-limiting.service';

// ✅ Guards are NOT normally added as providers unless they depend on DI.
// JwtAuthGuard & TenantGuard come from AuthModule, so no need to register them here.
@Module({
  imports: [
    AuthModule,
     ConfigModule,
     BehavioralAnalysisModule,
     DeviceFingerprintingModule, 
     SecurityModule,
    ],
  controllers: [ProtectedController],
  providers: [
    PrismaService,
    EventLogService,
    SessionGuard, 
    IPReputationService,
    BotDetectionService,
    RateLimitingService,
  ],
  exports: [SessionGuard], // 👈 optional: if other modules want to use it
})
export class ProtectedModule {}
