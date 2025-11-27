import { Module } from '@nestjs/common';
import { BehavioralAnalysisService } from './behavioral-analysis.service';
import { PrismaService } from '../prisma/prisma.service';
import { EventLogService } from '../events/event.service';
import { SecurityMonitoringService } from '../security/security-monitor.service';
import { IPReputationService } from '../ip-reputation/ip-reputation.service';
import { DeviceFingerprintingService } from '../device-fingerprinting/device-fingerprinting.service';

@Module({
  providers: [
    BehavioralAnalysisService,
    PrismaService,
    EventLogService,
    SecurityMonitoringService,
    IPReputationService,
    DeviceFingerprintingService,
  ],
  exports: [BehavioralAnalysisService],
})
export class BehavioralAnalysisModule {}