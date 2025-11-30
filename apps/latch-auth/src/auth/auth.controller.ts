// src/auth/auth.controller.ts
import { Throttle } from '@nestjs/throttler';
import { ClearCookiesUnauthorizedException } from './exceptions/clear-cookies-unauthorized.exception';
import {
  Body,
  Controller,
  Post,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import express from 'express';
import { AuthService } from './auth.service';
import { RequestOtpDto } from './dto/request-otp.dto';
import { VerifyOtpDto } from './dto/verify-otp.dto';
import { setRefreshCookies, clearRefreshCookies } from './utils/cookie.util';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { TenantGuard } from './guards/tenant.guard';
import { CsrfGuard } from './guards/csrf.guard';
import * as authTypes from './types/auth.types';
import { EventLogService } from '../events/event.service';
import { SessionGuard } from './guards/session.guard';

@Controller('auth')
export class AuthController {
  constructor(
    private auth: AuthService,
    private eventLogService: EventLogService,
  ) {}

  @Post('request-otp')
  // @Throttle('otpRequest')
  @Throttle({ otpRequest: { limit: 3, ttl: 300 } })
  async requestOtp(@Body() dto: RequestOtpDto, @Req() req: express.Request) {
    return this.auth.requestOtp(dto, {
      ipAddress: req.ip,
      userAgent: (req.headers['user-agent'] as string) || null,
    });
  }

  @Post('otpVerify')
  // @Throttle(6, 600)
  @Throttle({ otpVerify: { limit: 6, ttl: 600 } })
  async verifyOtp(
    @Body() dto: VerifyOtpDto,
    @Req() req: express.Request,
    @Res({ passthrough: true }) res: express.Response,
  ) {
    const result = await this.auth.verifyOtp(dto, {
      ipAddress: req.ip,
      userAgent: (req.headers['user-agent'] as string) || null,
    });

    setRefreshCookies(
      res,
      result.refreshToken,
      result.sessionId,
      result.csrfToken,
    );
    return result;
  }

  @UseGuards(CsrfGuard)
  @Post('refresh')
  // @Throttle(20, 60)
  @Throttle({ refrish: { limit: 20, ttl: 60 } })
  async refresh(
    @Req() req: authTypes.RequestWithCookies,
    @Res({ passthrough: true }) res: express.Response,
  ) {
    const refresh = req.cookies['latch_refresh'];
    const sessionId = req.cookies['latch_session'];

    if (!refresh || !sessionId) {
      await this.eventLogService.logEvent('REFRESH_FAILED', {
        userId: null,
        tenantId: null,
        metadata: {
          reason: 'missing_cookies',
          hasRefresh: !!refresh,
          hasSession: !!sessionId,
        },
        ipAddress: req.ip,
        userAgent: (req.headers['user-agent'] as string) || null,
        severity: 'SECURITY',
      });
      throw new UnauthorizedException('Missing cookies');
    }
    try {
      const result = await this.auth.refreshTokens(refresh, sessionId, {
        ipAddress: req.ip,
        userAgent: (req.headers['user-agent'] as string) || null,
      });

      setRefreshCookies(
        res,
        result.refreshToken,
        result.sessionId,
        result.csrfToken,
      );
      return result;
    } catch (error) {
      if (error instanceof ClearCookiesUnauthorizedException) {
        clearRefreshCookies(res); // ✅ clear stale cookies automatically
      }

      await this.eventLogService.logEvent('REFRESH_FAILED', {
        userId: null,
        tenantId: null,
        metadata: {
          reason: error?.message?.includes('revoked')
            ? 'session_revoked'
            : error?.message?.includes('expired')
              ? 'session_expired'
              : error?.message?.includes('not found')
                ? 'session_not_found'
                : 'refresh_token_invalid',
          sessionId,
          error: error.message,
        },
        ipAddress: req.ip,
        userAgent: (req.headers['user-agent'] as string) || null,
        severity: 'SECURITY',
      });
      throw error;
    }
  }

  @UseGuards(JwtAuthGuard, TenantGuard, CsrfGuard) // 🔒 Keep tenant + csrf
  @Post('logout')
  async logout(
    @Req() req: authTypes.RequestWithCookies,
    @Res({ passthrough: true }) res: express.Response,
  ) {
    console.log('✅ AuthController.logout HIT');
    const sessionId = req.cookies['latch_session']; // ← Read cookies FIRST
    let userId: string | null = null;
    let tenantId: string | null = null;
    let activeSessionsBefore = 0;

    if (sessionId) {
      const sessionUser = await this.auth.getUserBySessionId(sessionId, {
        ipAddress: req.ip,
        userAgent: (req.headers['user-agent'] as string) || null,
      });

      if (sessionUser) {
        userId = sessionUser.id;
        tenantId = sessionUser.tenantId;
        activeSessionsBefore = await this.auth.getActiveSessionCount(userId);

        await this.auth.revokeSession(sessionId, {
          ipAddress: req.ip,
          userAgent: (req.headers['user-agent'] as string) || null,
        });
      } else {
        // Log suspicious logout attempt (invalid session)
        await this.eventLogService.logEvent('LOGOUT_ATTEMPT_INVALID', {
          userId: null,
          tenantId: null,
          metadata: { sessionId, reason: 'session_not_found_or_expired' },
          ipAddress: req.ip,
          userAgent: (req.headers['user-agent'] as string) || null,
          severity: 'SECURITY',
        });
        // include sessionId in metadata to help forensic tracing, keep userId/tenantId null since we couldn't resolve them
        // Event is logged at SECURITY severity to highlight potential abuse.
        await this.eventLogService.logEvent('LOGOUT_ATTEMPT_INVALID', {
          userId: null,
          tenantId: null,
          metadata: { sessionId, reason: 'session_not_found_or_expired' },
          ipAddress: req.ip,
          userAgent: (req.headers['user-agent'] as string) || null,
          severity: 'SECURITY',
        });
      }
    }

    // ✅ Clear cookies AFTER reading them
    clearRefreshCookies(res);

    await this.eventLogService.logEvent('LOGOUT', {
      userId,
      tenantId,
      metadata: {
        ...(sessionId && { sessionId }),
        reason: userId ? 'user_initiated' : 'cleanup_or_invalid_session',
        activeSessionsBefore,
        activeSessionsAfter: userId ? Math.max(0, activeSessionsBefore - 1) : 0,
      },
      ipAddress: req.ip,
      userAgent: (req.headers['user-agent'] as string) || null,
      severity: 'INFO',
    });
    // Always log a LOGOUT event for an audit trail. If the session was invalid, userId/tenantId remain null.
    // `reason` helps distinguish the flow. `activeSessionsBefore/After` are best-effort (0 when not resolvable).
    await this.eventLogService.logEvent('LOGOUT', {
      userId,
      tenantId,
      metadata: {
        ...(sessionId && { sessionId }),
        reason: userId ? 'user_initiated' : 'cleanup_or_invalid_session',
        activeSessionsBefore,
        activeSessionsAfter: userId ? Math.max(0, activeSessionsBefore - 1) : 0,
      },
      ipAddress: req.ip,
      userAgent: (req.headers['user-agent'] as string) || null,
      severity: 'INFO',
    });
    return { ok: true };
  }

  @UseGuards(JwtAuthGuard, SessionGuard, TenantGuard, CsrfGuard)
  @Post('revoke-all')
  async revokeAll(
    @Req() req: authTypes.AuthenticatedRequest,
    @Res({ passthrough: true }) res: express.Response,
  ) {
    const revokedCount = await this.auth.revokeAllSessionsForUser(req.user.id, {
      ipAddress: req.ip,
      userAgent: (req.headers['user-agent'] as string) || null,
    });
    clearRefreshCookies(res);
    return { ok: true, revokedCount };
  }
}
