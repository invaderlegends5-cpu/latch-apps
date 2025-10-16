// src/auth/types/express.d.ts
import { Tenant } from '@prisma/client';

declare global {
  namespace Express {
    interface User {
      id: string;
      email?: string;
      sub?: string; // for JWT compatibility
      tenantId?: string;
      tenant?: string; // or Tenant if you attach full object
    }

    interface Request {
      user?: Express.User;
      tenant?: Tenant; // from TenantGuard
      normalizedIp?: string | null;
      normalizedUserAgent?: string | null;
    }
  }
}

export {};
