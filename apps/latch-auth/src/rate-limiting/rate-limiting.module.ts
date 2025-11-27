import { Module } from '@nestjs/common';
import { RateLimitingService } from './rate-limiting.service';
import { RateLimitingController } from './rate-limiting.controller';
import { PrismaService } from '../prisma/prisma.service';
import { EventLogService } from '../events/event.service';
import { RedisService } from '../redis/redis.service';

@Module({
  controllers: [RateLimitingController],
  providers: [
    RateLimitingService,
    PrismaService,
    EventLogService,
    RedisService,
  ],
  exports: [RateLimitingService],
})
export class RateLimitingModule {}