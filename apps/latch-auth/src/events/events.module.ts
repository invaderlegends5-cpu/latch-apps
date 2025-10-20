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

@Module({
  imports: [
    forwardRef(() => AuthModule),
    ConfigModule,
    PrismaModule, // ✅ Add this
  ],
  providers: [
    EventLogService,
    // PrismaService, // 🚫 Remove
  ],
  controllers: [EventController],
  exports: [EventLogService],
})
export class EventsModule {}