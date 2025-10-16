// src/auth/guards/roles.guard.ts
import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Logger,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Request } from 'express'; // ✅ Added
import { PrismaService } from '../../prisma/prisma.service';
import { EventLogService } from '../../events/event.service';
import { ROLES_KEY } from '../decorators/roles.decorator';

@Injectable()
export class RolesGuard implements CanActivate {
  private readonly logger = new Logger(RolesGuard.name);

  constructor(
    private readonly reflector: Reflector,
    private readonly prisma: PrismaService,
    private readonly eventLog: EventLogService,
  ) {}

  /**
   * Expected use:
   *  @UseGuards(JwtAuthGuard, TenantGuard, RolesGuard)
   *  @Roles('ADMIN')
   */
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const requiredRoles = this.reflector.getAllAndOverride<string[]>(
      ROLES_KEY,
      [context.getHandler(), context.getClass()],
    );

    if (!requiredRoles || requiredRoles.length === 0) return true;

    const req = context.switchToHttp().getRequest<Request>(); // ✅ Typed
    const user = req.user;

    if (!user || typeof user !== 'object') {
      await this.logDenied(
        null,
        null,
        requiredRoles,
        'missing_user_object',
        req,
      );
      this.logger.warn('RolesGuard: Missing or invalid req.user');
      throw new ForbiddenException('Not authorized');
    }

    const userId = user.sub ?? user.id;
    const tenantId = user.tenantId ?? user.tenant ?? null; // ✅ Simplified

    if (!userId) {
      await this.logDenied(
        null,
        tenantId,
        requiredRoles,
        'missing_user_id',
        req,
      );
      this.logger.warn('RolesGuard: user object missing id/sub');
      throw new ForbiddenException('Not authorized');
    }

    // 🔐 Tenant-scoped role lookup
    const userRoles = await this.prisma.userRole.findMany({
      where: {
        userId,
        ...(tenantId ? { role: { tenantId } } : {}),
      },
      include: { role: true },
    });

    const roleNames = userRoles.map((ur) => ur.role?.name).filter(Boolean);

    const allowed = requiredRoles.some((r) => roleNames.includes(r));

    if (!allowed) {
      await this.logDenied(
        userId,
        tenantId,
        requiredRoles,
        'role_mismatch',
        req,
      );
      this.logger.warn(
        `RolesGuard denied user=${userId} tenant=${tenantId ?? 'none'} required=${requiredRoles.join(',')}`,
      );
      throw new ForbiddenException('Insufficient role permissions');
    }

    await this.eventLog.logEvent('ROLE_ACCESS_GRANTED', {
      userId,
      tenantId,
      metadata: {
        requiredRoles,
        grantedRoles: roleNames,
        integrityChain: { enabled: true },
      },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'] ?? 'unknown', // ✅ Fallback
      severity: 'INFO',
    });

    return true;
  }

  private async logDenied(
    userId: string | null,
    tenantId: string | null,
    requiredRoles: string[],
    reason: string,
    req: Request, // ✅ Properly typed
  ) {
    try {
      await this.eventLog.logEvent('ROLE_ACCESS_DENIED', {
        userId,
        tenantId,
        metadata: {
          requiredRoles,
          reason,
          integrityChain: { enabled: true },
        },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] ?? 'unknown', // ✅ Fallback
        severity: 'SECURITY',
      });
    } catch (err) {
      this.logger.error('Failed to log ROLE_ACCESS_DENIED', err);
    }
  }
}
