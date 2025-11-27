// // src/events/events.module.ts
// import { Module, forwardRef } from '@nestjs/common';
// import { ConfigModule } from '@nestjs/config';
// import { PrismaService } from '../prisma/prisma.service';
// import { EventLogService } from './event.service';
// import { EventController } from './event.controller';
// import { AuthModule } from '../auth/auth.module';

// @Module({
//   imports: [forwardRef(() => AuthModule), ConfigModule],
//   providers: [EventLogService, PrismaService],
//   controllers: [EventController], // can remove if only backend uses it
//   exports: [EventLogService], // makes it reusable
// })
// export class EventsModule {}



//*****************after Docker */

// src/events/events.module.ts
import { Module, forwardRef } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { EventLogService } from './event.service';
import { EventController } from './event.controller';
import { AuthModule } from '../auth/auth.module';
import { PrismaModule } from '../prisma/prisma.module'; // ✅ Add this
import { IPReputationService } from '@/ip-reputation/ip-reputation.service';
import { TenantEventsController } from './tenant-events.controller';
import { SecurityModule } from '@/security/security.module';
import { BehavioralAnalysisService } from '@/behavioral-analysis/behavioral-analysis.service';
import { DeviceFingerprintingService } from '@/device-fingerprinting/device-fingerprinting.service';
import { BotDetectionService } from '@/bot-detection/bot-detection.service';
import { RateLimitingService } from '@/rate-limiting/rate-limiting.service';

@Module({
  imports: [
    forwardRef(() => AuthModule),
    ConfigModule,
    PrismaModule, 
    SecurityModule
  ],
  providers: [
    EventLogService,
    IPReputationService,
    BehavioralAnalysisService,
    DeviceFingerprintingService,
    BotDetectionService,
    RateLimitingService,
    // PrismaService, // 🚫 Remove
  ],
  controllers: [EventController, TenantEventsController],
  exports: [EventLogService],
})
export class EventsModule {}