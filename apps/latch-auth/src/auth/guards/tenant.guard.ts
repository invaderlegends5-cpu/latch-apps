// // src/auth/guards/tenant.guard.ts
// import {
//   CanActivate,
//   ExecutionContext,
//   Injectable,
//   ForbiddenException,
// } from '@nestjs/common';
// import { PrismaService } from '../../prisma/prisma.service';

// @Injectable()
// export class TenantGuard implements CanActivate {
//   constructor(private prisma: PrismaService) {}

//   // Expects client to send header: x-tenant-slug OR request body has tenantSlug
//   async canActivate(context: ExecutionContext): Promise<boolean> {
//     const req = context.switchToHttp().getRequest();
//     const tenantSlug =
//       req.headers['x-tenant-slug'] ||
//       req.body?.tenantSlug ||
//       req.query?.tenantSlug;
//     if (!tenantSlug) {
//       throw new ForbiddenException('Tenant not provided');
//     }

//     const tenant = await this.prisma.tenant.findUnique({
//       where: { slug: tenantSlug },
//     });
//     if (!tenant) {
//       throw new ForbiddenException('Tenant not found');
//     }

//     // attach tenant to request for downstream handlers
//     req.tenant = tenant;
//     // If user is authenticated, verify their tenant matches
//     if (req.user && req.user.tenantId && req.user.tenantId !== tenant.id) {
//       throw new ForbiddenException('Tenant mismatch');
//     }
//     return true;
//   }
// }

// src/auth/guards/tenant.guard.ts
import {
  CanActivate,
  ExecutionContext,
  Injectable,
  ForbiddenException,
} from '@nestjs/common';
import { Request } from 'express';
import { PrismaService } from '../../prisma/prisma.service';
import { EventLogService } from '../../events/event.service';

// interface SecureTenantRequest extends Request {
//   tenant?: { id: string; slug: string };
//   user?: {
//     id: string;
//     tenantId: string;
//     [key: string]: any;
//   };
// }

// Type guard functions to safely check object properties
function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object';
}

function extractTenantSlugFromHeaders(
  headers: Record<string, unknown>,
): string | null {
  const headerValue = headers['x-tenant-slug'];
  if (typeof headerValue === 'string') {
    return headerValue;
  }
  if (Array.isArray(headerValue) && headerValue.length > 0) {
    return String(headerValue[0]);
  }
  return null;
}

function extractTenantSlugFromBody(body: unknown): string | null {
  if (isRecord(body) && 'tenantSlug' in body) {
    const slug = body.tenantSlug;
    if (typeof slug === 'string') {
      return slug;
    }
  }
  return null;
}

function extractTenantSlugFromQuery(query: unknown): string | null {
  if (isRecord(query) && 'tenantSlug' in query) {
    const slug = query.tenantSlug;
    if (typeof slug === 'string') {
      return slug;
    }
    if (Array.isArray(slug) && slug.length > 0) {
      return String(slug[0]);
    }
  }
  return null;
}

@Injectable()
export class TenantGuard implements CanActivate {
  constructor(
    private prisma: PrismaService,
    private eventLogService: EventLogService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest();
    const ipAddress = req.ip;
    const userAgent = req.headers['user-agent'];

    const tenantSlug =
      extractTenantSlugFromHeaders(req.headers) ||
      extractTenantSlugFromBody(req.body) ||
      extractTenantSlugFromQuery(req.query);

    if (!tenantSlug) {
      await this.eventLogService.logEvent('TENANT_VALIDATION_ERROR', {
        userId: req.user?.id || null,
        tenantId: req.user?.tenantId || null,
        metadata: {
          reason: 'tenant_not_provided',
        },
        ipAddress,
        userAgent,
        severity: 'SECURITY',
      });
      throw new ForbiddenException('Tenant not provided');
    }

    if (!/^[a-zA-Z0-9-_]+$/.test(tenantSlug)) {
      await this.eventLogService.logEvent('TENANT_VALIDATION_ERROR', {
        userId: req.user?.id || null,
        tenantId: req.user?.tenantId || null,
        metadata: {
          reason: 'invalid_tenant_slug_format',
          tenantSlug: tenantSlug.substring(0, 50),
        },
        ipAddress,
        userAgent,
        severity: 'SECURITY',
      });
      throw new ForbiddenException('Invalid tenant slug format');
    }

    const tenant = await this.prisma.tenant.findUnique({
      where: { slug: tenantSlug },
      // select: { id: true, slug: true },
    });

    if (!tenant) {
      await this.eventLogService.logEvent('TENANT_VALIDATION_ERROR', {
        userId: req.user?.id || null,
        tenantId: req.user?.tenantId || null,
        metadata: {
          reason: 'tenant_not_found',
          tenantSlug: tenantSlug.substring(0, 50),
        },
        ipAddress,
        userAgent,
        severity: 'SECURITY',
      });
      throw new ForbiddenException('Tenant not found');
    }

    req.tenant = tenant;

    if (req.user?.tenantId && req.user.tenantId !== tenant.id) {
      await this.eventLogService.logEvent('TENANT_MISMATCH', {
        userId: req.user.id,
        tenantId: req.user.tenantId,
        metadata: {
          reason: 'tenant_mismatch',
          requestedTenantId: tenant.id,
          requestedTenantSlug: tenantSlug.substring(0, 50),
          userTenantId: req.user.tenantId,
        },
        ipAddress,
        userAgent,
        severity: 'SECURITY',
      });
      throw new ForbiddenException('Tenant mismatch');
    }

    return true;
  }
}
