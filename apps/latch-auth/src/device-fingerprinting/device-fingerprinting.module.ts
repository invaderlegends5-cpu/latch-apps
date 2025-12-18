//src/device-fingerprinting/device-fingerprinting.module.ts
import { Module } from '@nestjs/common';
import { DeviceFingerprintingService } from './device-fingerprinting.service';
import { DeviceFingerprintingController } from './device-fingerprinting.controller';
import { PrismaService } from '../prisma/prisma.service';
import { EventLogService } from '../events/event.service';
import { SecurityMonitoringService } from '../security/security-monitor.service';
import { RateLimitingModule } from '@/rate-limiting/rate-limiting.module';

@Module({
  imports: [
    RateLimitingModule,
  ],
  providers: [
    DeviceFingerprintingService,
    PrismaService,
    EventLogService,
    SecurityMonitoringService,
  ],
  controllers: [DeviceFingerprintingController],
  exports: [DeviceFingerprintingService],
})
export class DeviceFingerprintingModule {}