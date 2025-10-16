// src/app.module.ts (update)
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { ThrottlerModule } from '@nestjs/throttler';
import { ScheduleModule } from '@nestjs/schedule';
import { PrismaService } from './prisma/prisma.service';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { ProtectedModule } from './protected/protected.module';
import { EventLogService } from './events/event.service';
import { EventsModule } from './events/events.module';
import { SecurityModule } from './security/security.module';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    SecurityModule,
    ThrottlerModule.forRoot([
      {
        name: 'otpRequest', // 👈 named throttler
        ttl: 300, // 5 minutes
        limit: 3,
      },
      {
        name: 'otpVerify', // 👈 named throttler
        ttl: 600, // 10 minutes
        limit: 6,
      },
      {
        name: 'refresh', // 👈 named throttler
        ttl: 60, // 1 minute
        limit: 20,
      },
      {
        name: 'default', // fallback global
        ttl: 60,
        limit: 100,
      },
    ]),
    ScheduleModule.forRoot(),
    AuthModule,
    UsersModule,
    ProtectedModule,
    EventsModule,
  ],
  providers: [PrismaService,
    //  EventLogService
    ],
})
export class AppModule {}
