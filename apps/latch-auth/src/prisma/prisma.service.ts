// import { Injectable, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
// import { PrismaClient } from '@prisma/client';

// @Injectable()
// export class PrismaService extends PrismaClient implements OnModuleInit, OnModuleDestroy {
//   async onModuleInit() {
//     await this.$connect();
//   }

//   async onModuleDestroy() {
//     await this.$disconnect();
//   }

//   async enableShutdownHooks(app: any) {
//     // Use the 'never' type assertion which is more specific to Prisma
//     process.on('beforeExit', async () => {
//       await app.close();
//     });
//   }
// }

// src/prisma/prisma.service.ts
import { Injectable, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit, OnModuleDestroy {
  private currentTenantId?: string;

  setTenantId(tenantId: string) {
    this.currentTenantId = tenantId;
  }

  // Override or wrap queries to automatically include tenant scoping
  async findWithTenantScoping(model: any, args: any, tenantId: string) {
    return model.findMany({
      ...args,
      where: {
        ...args.where,
        tenantId, // Automatically enforce tenant isolation
      }
    });
  }

  async onModuleInit() {
    await this.$connect();
  }

  async onModuleDestroy() {
    await this.$disconnect();
  }
}
