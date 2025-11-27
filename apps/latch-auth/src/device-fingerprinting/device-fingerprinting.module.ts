import { Module } from '@nestjs/common';
import { DeviceFingerprintingService } from './device-fingerprinting.service';
import { PrismaService } from '../prisma/prisma.service';
import { EventLogService } from '../events/event.service';
import { SecurityMonitoringService } from '../security/security-monitor.service';

@Module({
  providers: [
    DeviceFingerprintingService,
    PrismaService,
    EventLogService,
    SecurityMonitoringService,
  ],
  exports: [DeviceFingerprintingService],
})
export class DeviceFingerprintingModule {}