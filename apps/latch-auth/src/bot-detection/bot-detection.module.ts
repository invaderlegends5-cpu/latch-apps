import { Module } from '@nestjs/common';
import { BotDetectionController } from './bot-detection.controller';
import { BotDetectionService } from './bot-detection.service';
import { DeviceFingerprintingService } from '../device-fingerprinting/device-fingerprinting.service';
import { PrismaService } from '../prisma/prisma.service';
import { EventLogService } from '../events/event.service';
import { BehavioralAnalysisService } from '../behavioral-analysis/behavioral-analysis.service';
import { RedisService } from '../redis/redis.service';
import { IPReputationService } from '@/ip-reputation/ip-reputation.service';
import { SecurityModule } from '@/security/security.module';
import { DeviceFingerprintingModule } from '@/device-fingerprinting/device-fingerprinting.module';
import { RateLimitingService } from '@/rate-limiting/rate-limiting.service';

@Module({
  imports: [
        SecurityModule, 
    DeviceFingerprintingModule, 
  ],
  controllers: [BotDetectionController],
  providers: [
    BotDetectionService,
    DeviceFingerprintingService,
    PrismaService,
    EventLogService,
    BehavioralAnalysisService,
    RedisService,
    IPReputationService,
    RateLimitingService,
  ],
  exports: [BotDetectionService],
})
export class BotDetectionModule {}