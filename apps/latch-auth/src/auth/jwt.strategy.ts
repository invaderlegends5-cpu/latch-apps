// src/auth/jwt.strategy.ts
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PrismaService } from '../prisma/prisma.service';
import { EventLogService } from '../events/event.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(
    private prisma: PrismaService,
    private eventLogService: EventLogService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: process.env.JWT_SECRET ?? 'dev_jwt_secret_change_me',
    });
  }

  /**
   * payload: { sub: userId, tenantId, sessionId, mfa, iat, exp }
   * This validate runs on every request protected by JwtAuthGuard.
   */
  async validate(payload: any) {
    if (!payload || !payload.sub) {
      // malformed token
      await this.eventLogService.logEvent('AUTH_JWT_FAILURE', {
        userId: null,
        tenantId: null,
        metadata: {
          reason: 'malformed_token',
          payloadKeys: Object.keys(payload || {}),
        },
        severity: 'SECURITY',
      });
      throw new UnauthorizedException('Invalid token');
    }

    // If token does not carry a sessionId, fail safe.
    if (!payload.sessionId) {
      await this.eventLogService.logEvent('AUTH_JWT_FAILURE', {
        userId: payload.sub,
        tenantId: payload.tenantId ?? null,
        metadata: { reason: 'missing_sessionId_in_token' },
        severity: 'SECURITY',
      });
      throw new UnauthorizedException('Invalid token (no session)');
    }

    // Load session and validate server-side session state
    const session = await this.prisma.session.findUnique({
      where: { id: payload.sessionId },
      include: { user: true },
    });

    // Not found, revoked, or expired -> unauthorized + log
    const now = new Date();
    if (!session) {
      await this.eventLogService.logEvent('AUTH_JWT_FAILURE', {
        userId: payload.sub,
        tenantId: payload.tenantId ?? null,
        metadata: { reason: 'session_not_found', sessionId: payload.sessionId },
        severity: 'SECURITY',
      });
      throw new UnauthorizedException('Session not found');
    }

    if (session.revoked) {
      await this.eventLogService.logEvent('AUTH_JWT_FAILURE', {
        userId: session.userId,
        tenantId: session.tenantId,
        metadata: { reason: 'session_revoked', sessionId: session.id },
        severity: 'SECURITY',
      });
      throw new UnauthorizedException('Session revoked');
    }

    if (session.expiresAt < now) {
      // optionally mark revoked
      await this.prisma.session.update({
        where: { id: session.id },
        data: { revoked: true },
      });

      await this.eventLogService.logEvent('SESSION_EXPIRED', {
        userId: session.userId,
        tenantId: session.tenantId,
        metadata: { sessionId: session.id },
        severity: 'SECURITY',
        // ipAddress: req.ip,
        // userAgent: req.headers['user-agent'],
      });

      throw new UnauthorizedException('Session expired');
    }

    // OK — return user payload that will be attached as req.user
    return {
      sub: payload.sub,
      tenantId: payload.tenantId,
      sessionId: payload.sessionId,
      mfa: payload.mfa ?? false,
    };
  }
}
