// // src/security/security.module.ts
// import { Module } from '@nestjs/common';
// import { SecurityController } from './security.controller';
// import { SecurityMonitoringService } from './security-monitor.service';
// import { EventLogService } from '../events/event.service';
// import { AdminGuard } from '../auth/guards/admin.guard';
// import { PrismaService } from '../prisma/prisma.service';
// import { ConfigService } from '@nestjs/config';

// @Module({
//   imports: [],
//   controllers: [SecurityController],
//   providers: [
//     SecurityMonitoringService,
//     EventLogService,
//     PrismaService,
//     ConfigService,
//     AdminGuard, // register guard so DI works
//   ],
//   exports: [SecurityMonitoringService],
// })
// export class SecurityModule {}
// src/security/security.module.ts
import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { SecurityController } from './security.controller';
import { SecurityMonitoringService } from './security-monitor.service';
import { EventLogService } from '../events/event.service';
import { PrismaModule } from '../prisma/prisma.module';

@Module({
  imports: [
    PrismaModule, // ✅ Properly inject PrismaService
    // Add EventsModule if EventLogService is exported from it
  ],
  controllers: [SecurityController],
  providers: [
    SecurityMonitoringService,
    EventLogService,
    ConfigService, // ✅ Kept as requested
    // ❌ REMOVED: AdminGuard (unsafe, deleted)
    // ❌ REMOVED: PrismaService (now provided by PrismaModule)
  ],
  exports: [SecurityMonitoringService],
})
export class SecurityModule {}
