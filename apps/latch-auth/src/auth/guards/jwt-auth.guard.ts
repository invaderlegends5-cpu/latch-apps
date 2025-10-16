// // src/auth/guards/jwt-auth.guard.ts
// import { ExecutionContext, Injectable } from '@nestjs/common';
// import { AuthGuard } from '@nestjs/passport';

// @Injectable()
// export class JwtAuthGuard extends AuthGuard('jwt') {
//   // can override handleRequest if custom logic needed
//   handleRequest(err: any, user: any, info: any, context: ExecutionContext) {
//     if (err || !user) {
//       return null; // let Nest handle unauthorized
//     }
//     return user;
//   }
// }

// src/auth/guards/jwt-auth.guard.ts
// src/auth/guards/jwt-auth.guard.ts
import {
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Request } from 'express';
// import { EventLogService } from 'src/events/event.service';
import { EventLogService } from '../../events/event.service';
import { ClearCookiesUnauthorizedException } from '../exceptions/clear-cookies-unauthorized.exception';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(private eventLogService: EventLogService) {
    super();
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<Request>();
    const ipAddress = req.ip;
    const userAgent = req.headers['user-agent'];

    try {
      const result = await super.canActivate(context);
      if (result) {
        return true;
      }

      await this.logAuthFailure(
        req,
        null,
        'authentication_failed',
        ipAddress,
        userAgent,
      );
      // throw new UnauthorizedException('Unauthorized');
      throw new ClearCookiesUnauthorizedException('Unauthorized');
    } catch (error) {
      await this.logAuthFailure(
        req,
        error,
        'authentication_error',
        ipAddress,
        userAgent,
      );
      // throw new UnauthorizedException('Unauthorized');
      throw new ClearCookiesUnauthorizedException('Unauthorized');
    }
  }

  private async logAuthFailure(
    req: Request,
    error: any,
    defaultReason: string,
    ipAddress: string | undefined,
    userAgent: string | undefined,
  ) {
    let reason = defaultReason;
    let errorType: string | null = null;
    let errorMessage: string | null = null;

    if (error && typeof error === 'object') {
      const err = error as Record<string, unknown>;

      if (typeof err.name === 'string') {
        errorType = err.name;
        if (err.name === 'JsonWebTokenError') {
          reason = 'invalid_token';
        } else if (err.name === 'TokenExpiredError') {
          reason = 'token_expired';
        }
      }

      if (typeof err.message === 'string') {
        errorMessage = err.message;
        if (err.message.includes('jwt must be provided')) {
          reason = 'missing_token';
        } else if (err.message.includes('invalid token')) {
          reason = 'malformed_token';
        }
      }
    }

    let tokenPrefix: string | null = null;
    const authHeader = req.headers.authorization;
    if (
      authHeader &&
      typeof authHeader === 'string' &&
      authHeader.startsWith('Bearer ')
    ) {
      const token = authHeader.substring(7);
      tokenPrefix = token.substring(0, Math.min(20, token.length));
      if (token.length > 20) tokenPrefix += '...';
    }

    await this.eventLogService.logEvent('AUTH_JWT_FAILURE', {
      userId: null,
      tenantId: null,
      metadata: {
        reason,
        errorType,
        errorMessage,
        hasToken: !!tokenPrefix,
        tokenPrefix,
      },
      ipAddress,
      userAgent,
      severity: 'SECURITY',
    });
  }
}
