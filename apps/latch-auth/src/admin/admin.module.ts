// src/admin/admin.module.ts
import { Module, forwardRef } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AdminService } from './admin.service';
import { AdminController } from './admin.controller';
import { EventsModule } from '../events/events.module';
import { PrismaModule } from '../prisma/prisma.module';
import { AuthModule } from '../auth/auth.module';
import { RedisModule } from '../redis/redis.module';
import { EventLogService } from '@/events/event.service';
import { IPReputationService } from '@/ip-reputation/ip-reputation.service';
import { SecurityMonitoringService } from '@/security/security-monitor.service';
import { RateLimitingService } from '@/rate-limiting/rate-limiting.service';

@Module({
  imports: [
    ConfigModule,
    PrismaModule,
    forwardRef(() => AuthModule), // For guards used in admin controller
    forwardRef(() => EventsModule), // For event logging in admin service
    RedisModule, // Global Redis module (but explicitly imported for clarity)
  ],
  controllers: [AdminController],
  providers: [
    AdminService,
     EventLogService,
    IPReputationService,
    SecurityMonitoringService,
    RateLimitingService,
  ],
  exports: [AdminService],
  // Optionally add if other modules need to import AdminModule's dependencies:
  // imports: [CommonModule]
})
export class AdminModule {}