// users.module.ts
import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { PrismaService } from '../prisma/prisma.service';
import { EventLogService } from 'src/events/event.service';
import { EventsModule } from 'src/events/events.module';
import { ConfigModule } from '@nestjs/config';

@Module({
  imports: [ConfigModule],
  providers: [
    UsersService,
    EventsModule,
    PrismaService,
    EventLogService, // ✅ Added EventLogService
  ],
  exports: [UsersService],
})
export class UsersModule {}
