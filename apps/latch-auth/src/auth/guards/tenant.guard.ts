// src/auth/guards/tenant.guard.ts
import {
  CanActivate,
  ExecutionContext,
  Injectable,
  ForbiddenException,
  BadRequestException,
  NotFoundException,
  UnauthorizedException,
  InternalServerErrorException,
} from '@nestjs/common';
import { Request } from 'express';
import { PrismaService } from '../../prisma/prisma.service';
import { EventLogService } from '../../events/event.service';
import { RateLimitingService } from '@/rate-limiting/rate-limiting.service';

interface AuthenticatedRequest extends Request {
  user?: {
    id: string;      // Often the primary DB ID of the user
    sub: string;     // The subject identifier from the JWT payload (often the same as id, but can be different)
    tenantId?: string;
    roles?: any[];   // Or a more specific type if roles are loaded here by JwtAuthGuard
    [key: string]: any; // Allow other properties potentially added by JwtAuthGuard
  };
  tenant?: any; // Or a specific tenant type if needed
}

// Helper to check if something is a plain object
function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object';
}

// 🔹 Flexible tenant slug extraction (covers all E2E routes)
function extractTenantSlug(req: Request): string | null {
  // 1️⃣ Try route params (best for NestJS controllers)
  if (req.params?.slug && typeof req.params.slug === 'string') {
    return req.params.slug;
  }
  if (req.params?.tenantId && typeof req.params.tenantId === 'string') {
    return req.params.tenantId;
  }
  // 2️⃣ Try header
  const headerValue = req.headers['x-tenant-slug'];
  if (typeof headerValue === 'string') return headerValue;
  if (Array.isArray(headerValue) && headerValue.length > 0)
    return String(headerValue[0]);

  // 3️⃣ Try body
  if (isRecord(req.body) && typeof req.body.tenantSlug === 'string') {
    return req.body.tenantSlug;
  }
  if (isRecord(req.body) && typeof req.body.tenantId === 'string') {
    return req.body.tenantId;
  }

  // 4️⃣ Try query param
  if (isRecord(req.query) && typeof req.query.tenantSlug === 'string') {
    return req.query.tenantSlug;
  }
    if (isRecord(req.query) && typeof req.query.tenantId === 'string') {
    return req.query.tenantId;
  }
  
  // 5️⃣ Try URL fallback (handles e.g. /v1/tenants/foo/stats)
  const match = req.url.match(/\/tenants\/([^/?]+)/);
  return match ? match[1] : null;
}

@Injectable()
export class TenantGuard implements CanActivate {
  constructor(
    private prisma: PrismaService,
    private eventLogService: EventLogService,
    private rateLimitService: RateLimitingService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<AuthenticatedRequest>();
    const ipAddress = req.ip;
    const userAgent = req.headers['user-agent'];

// Check rate limits BEFORE tenant validation
if (req.user?.tenantId) {
  const rateLimitCheck = await this.rateLimitService.isRequestAllowed(
    req.user.tenantId,
    req.url,
    ipAddress || 'unknown',
    req.user.id
  );

  if (!rateLimitCheck.allowed) {
    await this.eventLogService.logEvent('REFRESH_FAILED', {
      userId: req.user.id,
      tenantId: req.user.tenantId,
      metadata: {
        reason: 'rate_limit_exceeded',
        endpoint: req.url,
        retryAfter: rateLimitCheck.retryAfter,
        resetTime: rateLimitCheck.resetTime,
      },
      ipAddress,
      userAgent,
      severity: 'SECURITY',
    });
    
    throw new ForbiddenException('Rate limit exceeded. Please try again later.');
  }
}

 // 🔹 CRITICAL CHECK: Ensure the authentication layer fully resolved the user identity
    // If req.user.id is missing, the authentication chain is incomplete or compromised.
    // The guard should not proceed with authorization logic relying on a potentially invalid user object.
    if (!req.user?.id) {
      console.error("TenantGuard: Authentication incomplete or invalid. req.user.id is missing.");
      // Log a high-severity event indicating an authentication failure or potential tampering
      await this.eventLogService.logEvent('AUTHENTICATION_VERIFICATION_FAILED', {
        userId: req.user?.id || null, // Likely null/undefined, but log for completeness
        tenantId: req.user?.tenantId || null, // Log associated tenant if present
        metadata: {
          reason: 'incomplete_user_identity',
          details: 'req.user.id is missing after JwtAuthGuard passed',
          url: req.url,
          method: req.method,
        },
        ipAddress,
        userAgent,
        severity: 'SECURITY', // Mark this as a high-severity security concern
      });
      // Throw Unauthorized to indicate authentication failure, not authorization failure.
      // This provides a clearer distinction in logs and potential client behavior.
      throw new UnauthorizedException('Authentication incomplete or invalid. User identity could not be established.');
    }

    // At this point, req.user.id is guaranteed to exist.
    // Also check for tenantId which is essential for the core logic
    if (req.user.tenantId === undefined) { // Use '===' to catch null or undefined
      console.error("TenantGuard: Authentication incomplete or invalid. req.user.tenantId is missing.");
      await this.eventLogService.logEvent('AUTHENTICATION_VERIFICATION_FAILED', {
        userId: req.user.id, // Now known to be valid
        tenantId: null, // Explicitly null as it's missing
        metadata: {
          reason: 'incomplete_user_identity',
          details: 'req.user.tenantId is missing after JwtAuthGuard passed',
          url: req.url,
          method: req.method,
        },
        ipAddress,
        userAgent,
        severity: 'SECURITY',
      });
      throw new UnauthorizedException('Authentication incomplete or invalid. User tenant identity could not be established.');
    }

    const tenantSlug = extractTenantSlug(req);
 
    // 🔸 Missing slug → 400 (not 403)
    if (!tenantSlug) {
      await this.eventLogService.logEvent('TENANT_VALIDATION_ERROR', {
        userId: req.user.id || null,
        tenantId: req.user.tenantId || null,
        metadata: { reason: 'tenant_not_provided' },
        ipAddress,
        userAgent,
        severity: 'SECURITY',
      });
      throw new BadRequestException('Tenant slug missing');
    }

    // 🔸 Invalid slug → 400
    if (!/^[a-z0-9-]+$/i.test(tenantSlug)) {
      await this.eventLogService.logEvent('TENANT_VALIDATION_ERROR', {
        userId: req.user?.id || null,
        tenantId: req.user?.tenantId || null,
        metadata: { reason: 'invalid_tenant_slug_format', tenantSlug },
        ipAddress,
        userAgent,
        severity: 'SECURITY',
      });
      throw new BadRequestException('Invalid tenant slug format');
    }

    const tenant = await this.prisma.tenant.findUnique({
      where: { slug: tenantSlug },
    });
    console.log('🧩 [TenantGuard] findUnique result for slug:', tenantSlug, tenant);
    // 🔸 Tenant not found → 404 (not 403)
    if (!tenant) {
      console.log('❌ [TenantGuard] No tenant found for slug:', tenantSlug);
      await this.eventLogService.logEvent('TENANT_VALIDATION_ERROR', {
        userId: req.user.id || null,
        tenantId: req.user.tenantId || null,
        metadata: { reason: 'tenant_not_found', tenantSlug },
        ipAddress,
        userAgent,
        severity: 'SECURITY',
      });
       // Using ForbiddenException here is acceptable as it prevents leaking info about tenant existence.
      // Alternatively, consider NotFoundException if the risk of tenant enumeration is low.
      // Keeping ForbiddenException as per original intent.
      throw new ForbiddenException('Tenant mismatch');
    }

    // Assign tenant to request for downstream use
    req.tenant = tenant;

    // 🔹 Load user roles from DB to determine system-level privileges
    
    const userRoles = await this.prisma.userRole.findMany({
      where: { userId: req.user.id },
      include: { role: true },
    });

    if (!userRoles || !Array.isArray(userRoles)) {
      console.error("TenantGuard: userRole.findMany returned undefined or non-array:", userRoles);
      // Log a security event indicating a potential issue
      await this.eventLogService.logEvent('INTERNAL_ERROR', {
        userId: req.user?.id || null,
        tenantId: req.user?.tenantId || null,
        metadata: {
          reason: 'guard_prisma_error',
          action: 'TENANT_ACCESS_CHECK',
          details: 'userRole.findMany returned invalid data',
        },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] as string,
        severity: 'CRITICAL', // Or 'ERROR'
      });
      // Throw an error that reflects the internal failure.
      // InternalServerErrorException is often appropriate here.
      throw new InternalServerErrorException('An internal error occurred while checking permissions.');
    }

    // 🔹 A user with any system-level role (role.isSystem = true) can access any tenant
    const hasSystemLevelRole = userRoles.some(ur => ur.role.isSystem);
    const hasCrossTenantPrivilege = userRoles.some(ur =>
      Array.isArray(ur.role.privileges) &&
      ur.role.privileges.includes('cross_tenant_access'),
    );

   // 🔸 Tenant isolation (skip for system-level roles)
   if (
    !hasSystemLevelRole &&
    !hasCrossTenantPrivilege &&
    req.user.tenantId &&
    req.user.tenantId !== tenant.id
  ) {
    console.log('❌ [TenantGuard] Tenant mismatch:', {
      userTenantId: req.user.tenantId,
      requestedTenantId: tenant.id,
      userId: req.user?.id,
    });
  await this.eventLogService.logEvent('TENANT_MISMATCH', {
    userId: req.user.id,
    tenantId: req.user.tenantId,
    metadata: {
      reason: 'tenant_mismatch',
      requestedTenantId: tenant.id,
      requestedTenantSlug: tenantSlug,
    },
    ipAddress,
    userAgent,
    severity: 'SECURITY',
  });
  throw new ForbiddenException('Tenant mismatch');
}
console.log('✅ [TenantGuard] Access granted for user:', req.user?.id);
console.log('[TenantGuard.canActivate] Guard completed, returning true.');
    return true;
  }
}
