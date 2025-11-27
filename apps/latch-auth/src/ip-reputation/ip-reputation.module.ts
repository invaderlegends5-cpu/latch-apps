import { Module } from '@nestjs/common';
import { ScheduleModule } from '@nestjs/schedule';
import { IPReputationService } from './ip-reputation.service';
import { IPReputationController } from './ip-reputation.controller';
import { EventLogService } from '../events/event.service';
import { SecurityMonitoringService } from '../security/security-monitor.service';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '@/redis/redis.service';
import { RateLimitingService } from '@/rate-limiting/rate-limiting.service';

@Module({
  imports: [
    ScheduleModule.forRoot(),
  ],
  controllers: [IPReputationController],
  providers: [
    IPReputationService,
    EventLogService,
    SecurityMonitoringService,
    PrismaService,
    RedisService,
    RateLimitingService,
  ],
  exports: [IPReputationService],
})
export class IPReputationModule {}