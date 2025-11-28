// src/test/test-app.module.ts

import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';

// Only import essential functional modules
import { AuthModule } from '@/auth/auth.module';
import { UsersModule } from '@/users/users.module';
import { TenantsModule } from '@/tenants/tenants.module';
import { AdminModule } from '@/admin/admin.module';

// DO NOT IMPORT AppModule
// DO NOT IMPORT RedisModule, RateLimitingModule, SecurityModule
// DO NOT IMPORT ThrottlerModule or ScheduleModule
// DO NOT IMPORT BehavioralAnalysisModule, BotDetectionModule
// DO NOT IMPORT EventsModule

@Module({
  imports: [
    // A lightweight JWT module for authentication chain
    JwtModule.register({
      secret: 'test-secret',
    }),

    // Only include functional modules needed for your routes
    AuthModule,
    UsersModule,
    TenantsModule,
    AdminModule,
  ],
})
export class TestAppModule {}
