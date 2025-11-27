//src/tenants/tenants.module.ts
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { TenantsService } from './tenants.service';
import { TenantsController } from './tenants.controller';
import { TenantEventsController } from '../events/tenant-events.controller'; // Add this
import { EventLogService } from '../events/event.service';
import { PrismaModule } from '../prisma/prisma.module';
import { AuthModule } from '../auth/auth.module';
import { IPReputationService } from '@/ip-reputation/ip-reputation.service';
import { RateLimitingService } from '@/rate-limiting/rate-limiting.service';
import { SecurityMonitoringService } from '@/security/security-monitor.service';
import { BehavioralAnalysisService } from '@/behavioral-analysis/behavioral-analysis.service';
import { DeviceFingerprintingService } from '@/device-fingerprinting/device-fingerprinting.service';
import { BotDetectionService } from '@/bot-detection/bot-detection.service';

@Module({
  imports: [
    ConfigModule,
    PrismaModule,
    AuthModule, // For the guards used in TenantEventsController
  ],
  controllers: [
    TenantsController,
    TenantEventsController, 
  ],
  providers: [
    TenantsService,
    EventLogService, 
    IPReputationService,
    RateLimitingService,
    SecurityMonitoringService,
    BehavioralAnalysisService,
    DeviceFingerprintingService,
    BotDetectionService,
  ],
  exports: [TenantsService],
})
export class TenantsModule {}