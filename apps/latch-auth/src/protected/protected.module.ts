// // src/protected/protected.module.ts
// import { Module } from '@nestjs/common';
// import { ProtectedController } from './protected.controller';
// import { PrismaService } from '../prisma/prisma.service';
// import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
// import { TenantGuard } from '../auth/guards/tenant.guard';

// @Module({
//   imports: [],
//   controllers: [ProtectedController],
//   providers: [PrismaService, JwtAuthGuard, TenantGuard],
// })
// export class ProtectedModule {}

// src/protected/protected.module.ts
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { ProtectedController } from './protected.controller';
import { PrismaService } from '../prisma/prisma.service';
import { EventLogService } from 'src/events/event.service';
import { SessionGuard } from 'src/auth/guards/session.guard';
import { AuthModule } from 'src/auth/auth.module';

// ✅ Guards are NOT normally added as providers unless they depend on DI.
// JwtAuthGuard & TenantGuard come from AuthModule, so no need to register them here.
@Module({
  imports: [AuthModule, ConfigModule],
  controllers: [ProtectedController],
  providers: [
    PrismaService,
    EventLogService,
    SessionGuard, // 👈 add here so it can be injected
  ],
  exports: [SessionGuard], // 👈 optional: if other modules want to use it
})
export class ProtectedModule {}
