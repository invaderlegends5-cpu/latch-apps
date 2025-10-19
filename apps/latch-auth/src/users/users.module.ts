// // users.module.ts
// import { Module } from '@nestjs/common';
// import { UsersService } from './users.service';
// import { PrismaService } from '../prisma/prisma.service';
// import { EventLogService } from '../events/event.service';
// import { EventsModule } from '../events/events.module';
// import { ConfigModule } from '@nestjs/config';

// @Module({
//   imports: [ConfigModule],
//   providers: [
//     UsersService,
//     EventsModule,
//     PrismaService,
//     EventLogService, // ✅ Added EventLogService
//   ],
//   exports: [UsersService],
// })
// export class UsersModule {}

//**********after Docker //

// src/users/users.module.ts
import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { PrismaModule } from '../prisma/prisma.module';     // ✅ Add this
import { EventsModule } from '../events/events.module';     // ✅ Keep this
import { ConfigModule } from '@nestjs/config';

@Module({
  imports: [
    ConfigModule,
    PrismaModule,   // ✅ Add this
    EventsModule,   // ✅ Move from providers to imports
  ],
  providers: [
    UsersService,   // ✅ Only your own service
    // EventsModule,        // 🚫 Remove
    // PrismaService,       // 🚫 Remove  
    // EventLogService,     // 🚫 Remove
  ],
  exports: [UsersService],
})
export class UsersModule {}
