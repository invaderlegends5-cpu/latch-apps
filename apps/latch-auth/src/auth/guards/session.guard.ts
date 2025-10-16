// // src/auth/guards/session.guard.ts
// import {
//   CanActivate,
//   ExecutionContext,
//   Injectable,
//   UnauthorizedException,
// } from '@nestjs/common';
// import { Request } from 'express';
// import { AuthService } from '../auth.service';
// import { EventLogService } from 'src/events/event.service';

// @Injectable()
// export class SessionGuard implements CanActivate {
//   constructor(
//     private readonly authService: AuthService,
//     private readonly eventLogService: EventLogService,
//   ) {}

//   async canActivate(context: ExecutionContext): Promise<boolean> {
//     const req = context.switchToHttp().getRequest<Request & { user?: any }>();

//     // JWT payload is attached by JwtStrategy
//     const { user } = req;
//     const ipAddress = req.ip;
//     const userAgent = req.headers['user-agent'];

//     if (!user?.sessionId) {
//       await this.eventLogService.logEvent('SESSION_INVALID', {
//         userId: user?.sub || null,
//         tenantId: user?.tenantId || null,
//         metadata: { reason: 'missing_session_in_payload' },
//         ipAddress,
//         userAgent,
//         severity: 'SECURITY',
//       });
//       throw new UnauthorizedException('Missing or invalid session');
//     }

//     const sessionUser = await this.authService.getUserBySessionId(
//       user.sessionId,
//       { ipAddress, userAgent },
//     );

//     if (!sessionUser) {
//       // getUserBySessionId already logs SESSION_EXPIRED or SESSION_REVOKED
//       throw new UnauthorizedException('Invalid or expired session');
//     }

//     // Attach tenant to request (so TenantGuard works)
//     req.tenant = { id: sessionUser.tenantId, slug: 'unknown' };

//     return true;
//   }
// }

// src/auth/guards/session.guard.ts
import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Request } from 'express';
import { AuthService } from '../auth.service';
import { EventLogService } from '../../events/event.service';
import { ClearCookiesUnauthorizedException } from '../exceptions/clear-cookies-unauthorized.exception';

@Injectable()
export class SessionGuard implements CanActivate {
  constructor(
    private readonly authService: AuthService,
    private readonly eventLogService: EventLogService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context
      .switchToHttp()
      .getRequest<Request & { user?: any; tenant?: any }>();

    const ipAddress = req.ip;
    const userAgent = (req.headers['user-agent'] as string) || null;

    // JwtStrategy attaches the JWT payload to req.user
    const jwtPayload = req.user;

    if (!jwtPayload || !jwtPayload.sessionId) {
      await this.eventLogService.logEvent('SESSION_REVOKE', {
        userId: jwtPayload?.sub ?? null,
        tenantId: jwtPayload?.tenantId ?? null,
        metadata: { reason: 'missing_session_in_token' },
        ipAddress,
        userAgent,
        severity: 'SECURITY',
      });
      // throw new UnauthorizedException('Missing or invalid session');
      throw new ClearCookiesUnauthorizedException('Missing or invalid session');
    }

    // ✅ Validate session in DB (revoked/expired)
    const sessionUser = await this.authService.getUserBySessionId(
      jwtPayload.sessionId,
      { ipAddress, userAgent },
    );

    if (!sessionUser) {
      // Already logged inside getUserBySessionId, but we add another explicit log for traceability
      await this.eventLogService.logEvent(
        'AUTHENTICATION_VERIFICATION_FAILED',
        {
          userId: jwtPayload?.sub ?? null,
          tenantId: jwtPayload?.tenantId ?? null,
          metadata: {
            reason: 'session_invalid_or_expired',
            sessionId: jwtPayload.sessionId,
          },
          ipAddress,
          userAgent,
          severity: 'SECURITY',
        },
      );
      // throw new UnauthorizedException('Invalid or expired session');
      throw new ClearCookiesUnauthorizedException('Invalid or expired session');
    }

    // ✅ Only attach enriched user if session is valid
    req.user = {
      ...jwtPayload, // from token
      id: jwtPayload.sub,
      sessionId: jwtPayload.sessionId,
      tenantId: jwtPayload.tenantId,
      // from DB
      dbUserId: sessionUser.id,
      dbTenantId: sessionUser.tenantId,
    };

    req.tenant = { id: sessionUser.tenantId, slug: undefined };

    // console.log('[SessionGuard] user payload:', req.user);

    return true;
  }
}
