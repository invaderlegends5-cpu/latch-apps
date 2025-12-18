// src/auth/guards/csrf.guard.ts
import {
  CanActivate,
  ExecutionContext,
  Injectable,
  ForbiddenException,
  UnauthorizedException,
} from '@nestjs/common';
import { Request } from 'express';
import { PrismaService } from '../../prisma/prisma.service';
import { CSRF_COOKIE_NAME, SESSION_COOKIE_NAME } from '../utils/cookie.util';
import { EventLogService } from '../../events/event.service';

interface CsrfRequest extends Request {
  cookies: {
    [CSRF_COOKIE_NAME]?: string;
    [SESSION_COOKIE_NAME]?: string;
  };
  body: {
    sessionId?: string;
  };
}

@Injectable()
export class CsrfGuard implements CanActivate {
  constructor(
    private prisma: PrismaService,
    private eventLogService: EventLogService,
  ) {}


async canActivate(context: ExecutionContext): Promise<boolean> {
  const req = context.switchToHttp().getRequest<CsrfRequest>();

  const ipAddress = req.ip;
  const userAgent = req.headers['user-agent'];

  const rawHeaderToken = req.headers['x-csrf-token'];
  const rawXsrfToken = req.headers['x-xsrf-token'];

  let headerToken: string | undefined;
  let xsrfToken: string | undefined;

  // Safe access for debug logging
  const hasLatchCsrfCookie = req.cookies && req.cookies['latch_csrf'] !== undefined;
  const latchCsrfCookieValue = req.cookies ? req.cookies['latch_csrf'] : undefined;
  const hasLatchSessionCookie = req.cookies && req.cookies['latch_session'] !== undefined;
  const latchSessionCookieValue = req.cookies ? req.cookies['latch_session'] : undefined;

  

  // Normalize x-csrf-token
  if (Array.isArray(rawHeaderToken)) {
    if (rawHeaderToken.length > 1) {
      await this.eventLogService.logEvent('SECURITY_CSRF_ERROR', {
        userId: null,
        tenantId: null,
        metadata: {
          reason: 'multiple_csrf_tokens',
          tokenCount: rawHeaderToken.length,
        },
        ipAddress,
        userAgent,
        severity: 'SECURITY',
      });
      throw new ForbiddenException('Multiple CSRF tokens not allowed');
    }
    headerToken = rawHeaderToken[0];
  } else if (rawHeaderToken) {
    headerToken = String(rawHeaderToken);
  }

  // Normalize x-xsrf-token
  if (Array.isArray(rawXsrfToken)) {
    if (rawXsrfToken.length > 1) {
      await this.eventLogService.logEvent('SECURITY_CSRF_ERROR', {
        userId: null,
        tenantId: null,
        metadata: {
          reason: 'multiple_xsrf_tokens',
          tokenCount: rawXsrfToken.length,
        },
        ipAddress,
        userAgent,
        severity: 'SECURITY',
      });
      throw new ForbiddenException('Multiple XSRF tokens not allowed');
    }
    xsrfToken = rawXsrfToken[0];
  } else if (rawXsrfToken) {
    xsrfToken = String(rawXsrfToken);
  }

  const csrfToken = headerToken || xsrfToken;

  // --- CRITICAL FIX: Safely access cookie token ---
  // const cookieToken = req.cookies[CSRF_COOKIE_NAME]; // OLD LINE - CAUSES ERROR
  const cookieToken = req.cookies ? req.cookies['latch_csrf'] : undefined; // NEW LINE - SAFELY ACCESSES COOKIE

  // --- CRITICAL FIX: Safely access session ID ---
  // const sessionId = req.cookies[SESSION_COOKIE_NAME] || req.body?.sessionId; // OLD LINE - COULD CAUSE ERROR
  const sessionIdFromCookie = req.cookies ? req.cookies['latch_session'] : undefined; // NEW LINE - SAFELY ACCESSES SESSION COOKIE
  const sessionId = sessionIdFromCookie || req.body?.sessionId; // Use the safely retrieved value or body

  console.log('🔍 CSRF Guard Debug:', {
    url: req.url,
    method: req.method,
    hasXCsrf: !!req.headers['x-csrf-token'],
    xCsrf: req.headers['x-csrf-token'],
    hasLatchCsrfCookie: req.cookies ? !!req.cookies['latch_csrf'] : false,
    latchCsrfCookie: req.cookies ? req.cookies['latch_csrf'] : undefined,
    hasLatchSessionCookie: req.cookies ? !!req.cookies['latch_session'] : false,
    latchSessionCookie: req.cookies ? req.cookies['latch_session'] : undefined,
    sessionIdFromCookie: req.cookies ? req.cookies['latch_session'] : undefined,
    sessionIdFromBody: req.body?.sessionId,
    sessionId: sessionId, // The resolved session ID
  });
  console.log('🔍 CSRF Token Validation:', {
    headerToken: csrfToken,
    cookieToken: cookieToken,
    sessionId: sessionId,
  });

  const isRefreshEndpoint =
    req.url.endsWith('/refresh') && req.method === 'POST';

  // --- Case 1: Missing tokens (true CSRF failure) ---
  // The checks for !csrfToken, !cookieToken, !sessionId are now safe
  if (!csrfToken || !cookieToken || !sessionId) {
    const hasSessionButMissingCsrf =
      sessionId && (!csrfToken || !cookieToken);
    const completelyMissingSession = !sessionId;

    if (isRefreshEndpoint) {
      // For refresh calls, treat missing CSRF as REFRESH_FAILED not CSRF
      await this.eventLogService.logEvent('REFRESH_FAILED', {
        userId: null,
        tenantId: null,
        metadata: {
          reason: hasSessionButMissingCsrf
            ? 'missing_csrf_tokens_with_session'
            : 'missing_session_cookie',
          hasCsrfToken: !!csrfToken,
          hasCookieToken: !!cookieToken,
          hasSessionId: !!sessionId,
        },
        ipAddress,
        userAgent,
        severity: 'SECURITY',
      });
      throw new UnauthorizedException('Invalid refresh attempt');
    }

    // Non-refresh endpoints keep CSRF semantics
    await this.eventLogService.logEvent('SECURITY_CSRF_ERROR', {
      userId: null,
      tenantId: null,
      metadata: {
        reason: 'missing_tokens_or_session',
        hasCsrfToken: !!csrfToken,
        hasCookieToken: !!cookieToken,
        hasSessionId: !!sessionId,
      },
      ipAddress,
      userAgent,
      severity: 'SECURITY',
    });
    throw new ForbiddenException('Missing CSRF token or session');
  }

  // --- Case 2: Format validation (true CSRF failure) ---
  if (csrfToken.length < 16 || csrfToken.length > 256) {
    await this.eventLogService.logEvent('SECURITY_CSRF_ERROR', {
      userId: null,
      tenantId: null,
      metadata: {
        reason: 'invalid_csrf_token_format',
        tokenLength: csrfToken.length,
      },
      ipAddress,
      userAgent,
      severity: 'SECURITY',
    });
    throw new ForbiddenException('Invalid CSRF token format');
  }
  if (cookieToken.length < 16 || cookieToken.length > 256) {
    await this.eventLogService.logEvent('SECURITY_CSRF_ERROR', {
      userId: null,
      tenantId: null,
      metadata: {
        reason: 'invalid_cookie_token_format',
        tokenLength: cookieToken.length,
      },
      ipAddress,
      userAgent,
      severity: 'SECURITY',
    });
    throw new ForbiddenException('Invalid CSRF cookie token format');
  }

  // --- Case 3: Header vs cookie mismatch (true CSRF failure) ---
  if (csrfToken !== cookieToken) {
    await this.eventLogService.logEvent('SECURITY_CSRF_MISMATCH', {
      userId: null,
      tenantId: null,
      metadata: {
        reason: 'header_vs_cookie_mismatch',
        csrfTokenLength: csrfToken.length,
        cookieTokenLength: cookieToken.length,
        sessionId,
      },
      ipAddress,
      userAgent,
      severity: 'SECURITY',
    });
    throw new ForbiddenException('CSRF token mismatch (header vs cookie)');
  }

  // --- Case 4: DB session validation ---
  const session = await this.prisma.session.findUnique({
    where: { id: sessionId },
  });

  if (
    !session ||
    session.revoked ||
    !session.csrfToken ||
    session.csrfToken !== cookieToken
  ) {
    if (isRefreshEndpoint) {
      // For refresh endpoint, distinguish between session issues and CSRF issues
      if (!session) {
        // Session not found - this is an authentication issue
        throw new UnauthorizedException('Session not found');
      } else if (session.revoked) {
        // Session revoked - this is an authentication issue
        throw new UnauthorizedException('Session revoked');
      } else if (!session.csrfToken || session.csrfToken !== cookieToken) {
        // CSRF token mismatch in DB - this is a security/CSRF issue
        await this.eventLogService.logEvent('SECURITY_CSRF_MISMATCH', {
          userId: session.userId,
          tenantId: session.tenantId,
          metadata: {
            reason: 'db_vs_cookie_mismatch',
            sessionId,
          },
          ipAddress,
          userAgent,
          severity: 'SECURITY',
        });
        throw new ForbiddenException('Invalid CSRF token for session');
      }
    } else {
      // Non-refresh endpoints → still log as CSRF
      await this.eventLogService.logEvent('SECURITY_CSRF_MISMATCH', {
        userId: session?.userId ?? null,
        tenantId: session?.tenantId ?? null,
        metadata: {
          reason: session ? 'db_vs_cookie_mismatch' : 'session_not_found',
          sessionId,
        },
        ipAddress,
        userAgent,
        severity: 'SECURITY',
      });
      throw new ForbiddenException('Invalid CSRF token for session');
    }
  }

  return true;
}
}
