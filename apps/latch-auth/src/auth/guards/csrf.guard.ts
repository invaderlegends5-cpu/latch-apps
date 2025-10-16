// // src/auth/guards/csrf.guard.ts
// import {
//   CanActivate,
//   ExecutionContext,
//   Injectable,
//   ForbiddenException,
// } from '@nestjs/common';
// import { Request } from 'express';
// import { PrismaService } from '../../prisma/prisma.service';
// import { CSRF_COOKIE_NAME, SESSION_COOKIE_NAME } from '../utils/cookie.util';
// import { EventLogService } from 'src/events/event.service';

// interface CsrfRequest extends Request {
//   cookies: {
//     [CSRF_COOKIE_NAME]?: string;
//     [SESSION_COOKIE_NAME]?: string;
//   };
//   body: {
//     sessionId?: string;
//   };
// }

// @Injectable()
// export class CsrfGuard implements CanActivate {
//   constructor(
//     private prisma: PrismaService,
//     private eventLogService: EventLogService,
//   ) {}

//   async canActivate(context: ExecutionContext): Promise<boolean> {
//     const req = context.switchToHttp().getRequest<CsrfRequest>();

//     // Get request context for logging
//     const ipAddress = req.ip;
//     const userAgent = req.headers['user-agent'];

//     // Read CSRF header with proper type safety
//     const rawHeaderToken = req.headers['x-csrf-token'];
//     const rawXsrfToken = req.headers['x-xsrf-token'];

//     // Safely extract token value - handle both string and array cases
//     let headerToken: string | undefined;
//     let xsrfToken: string | undefined;

//     // Process x-csrf-token header
//     if (rawHeaderToken !== undefined && rawHeaderToken !== null) {
//       if (Array.isArray(rawHeaderToken)) {
//         // If it's an array, take first element (but validate it's a single value)
//         if (rawHeaderToken.length > 1) {
//           await this.eventLogService.logEvent('SECURITY_CSRF_ERROR', {
//             userId: null,
//             tenantId: null,
//             metadata: {
//               reason: 'multiple_csrf_tokens',
//               tokenCount: rawHeaderToken.length,
//             },
//             ipAddress,
//             userAgent,
//             severity: 'SECURITY',
//           });
//           throw new ForbiddenException('Multiple CSRF tokens not allowed');
//         }
//         headerToken = rawHeaderToken[0];
//       } else {
//         headerToken = String(rawHeaderToken);
//       }
//     }

//     // Process x-xsrf-token header
//     if (rawXsrfToken !== undefined && rawXsrfToken !== null) {
//       if (Array.isArray(rawXsrfToken)) {
//         // If it's an array, take first element (but validate it's a single value)
//         if (rawXsrfToken.length > 1) {
//           await this.eventLogService.logEvent('SECURITY_CSRF_ERROR', {
//             userId: null,
//             tenantId: null,
//             metadata: {
//               reason: 'multiple_xsrf_tokens',
//               tokenCount: rawXsrfToken.length,
//             },
//             ipAddress,
//             userAgent,
//             severity: 'SECURITY',
//           });
//           throw new ForbiddenException('Multiple XSRF tokens not allowed');
//         }
//         xsrfToken = rawXsrfToken[0];
//       } else {
//         xsrfToken = String(rawXsrfToken);
//       }
//     }

//     // Select final token (prefer x-csrf-token over x-xsrf-token)
//     const csrfToken = headerToken || xsrfToken;
//     const cookieToken = req.cookies[CSRF_COOKIE_NAME];
//     const sessionId = req.cookies[SESSION_COOKIE_NAME] || req.body?.sessionId;

//     // Enhanced security validation
//     if (!csrfToken || !cookieToken || !sessionId) {
//       await this.eventLogService.logEvent('SECURITY_CSRF_ERROR', {
//         userId: null,
//         tenantId: null,
//         metadata: {
//           reason: 'missing_tokens_or_session',
//           hasCsrfToken: !!csrfToken,
//           hasCookieToken: !!cookieToken,
//           hasSessionId: !!sessionId,
//         },
//         ipAddress,
//         userAgent,
//         severity: 'SECURITY',
//       });
//       throw new ForbiddenException('Missing CSRF token or session');
//     }

//     // Validate token format (prevent empty strings, ensure reasonable length)
//     if (csrfToken.length < 16 || csrfToken.length > 256) {
//       await this.eventLogService.logEvent('SECURITY_CSRF_ERROR', {
//         userId: null,
//         tenantId: null,
//         metadata: {
//           reason: 'invalid_csrf_token_format',
//           tokenLength: csrfToken.length,
//         },
//         ipAddress,
//         userAgent,
//         severity: 'SECURITY',
//       });
//       throw new ForbiddenException('Invalid CSRF token format');
//     }

//     // Validate cookie token format
//     if (cookieToken.length < 16 || cookieToken.length > 256) {
//       await this.eventLogService.logEvent('SECURITY_CSRF_ERROR', {
//         userId: null,
//         tenantId: null,
//         metadata: {
//           reason: 'invalid_cookie_token_format',
//           tokenLength: cookieToken.length,
//         },
//         ipAddress,
//         userAgent,
//         severity: 'SECURITY',
//       });
//       throw new ForbiddenException('Invalid CSRF cookie token format');
//     }

//     // Header must equal cookie (double-submit validation)
//     if (csrfToken !== cookieToken) {
//       console.log('CSRF MISMATCH:', {
//         received: csrfToken.substring(0, 10) + '...',
//         expected: cookieToken.substring(0, 10) + '...',
//       });

//       await this.eventLogService.logEvent('SECURITY_CSRF_MISMATCH', {
//         userId: null,
//         tenantId: null,
//         metadata: {
//           reason: 'header_vs_cookie_mismatch',
//           csrfTokenLength: csrfToken.length,
//           cookieTokenLength: cookieToken.length,
//           sessionId: sessionId,
//         },
//         ipAddress,
//         userAgent,
//         severity: 'SECURITY',
//       });
//       throw new ForbiddenException('CSRF token mismatch (header vs cookie)');
//     }

//     // Verify session has that CSRF token stored in database
//     const session = await this.prisma.session.findUnique({
//       where: { id: sessionId },
//     });
//     const isRefreshEndpoint =
//       req.url.endsWith('/refresh') && req.method === 'POST';
//     if (!session) {
//       if (isRefreshEndpoint) {
//         // Log as refresh failure for better threat intelligence
//         await this.eventLogService.logEvent('REFRESH_FAILED', {
//           // ... refresh-specific metadata
//         });
//       } else {
//         await this.eventLogService.logEvent('SECURITY_CSRF_ERROR', {
//           userId: null,
//           tenantId: null,
//           metadata: {
//             reason: 'session_not_found',
//             sessionId,
//           },
//           ipAddress,
//           userAgent,
//           severity: 'SECURITY',
//         });
//       }
//       throw new ForbiddenException('Session missing');
//     }

//     if (session.revoked) {
//       await this.eventLogService.logEvent('SECURITY_CSRF_ERROR', {
//         userId: session.userId,
//         tenantId: session.tenantId,
//         metadata: {
//           reason: 'session_revoked',
//           sessionId,
//         },
//         ipAddress,
//         userAgent,
//         severity: 'SECURITY',
//       });
//       throw new ForbiddenException('Session revoked');
//     }

//     if (!session.csrfToken || session.csrfToken !== cookieToken) {
//       await this.eventLogService.logEvent('SECURITY_CSRF_MISMATCH', {
//         userId: session.userId,
//         tenantId: session.tenantId,
//         metadata: {
//           reason: 'db_vs_cookie_mismatch',
//           sessionId,
//           cookieTokenPrefix: cookieToken.substring(0, 8),
//           dbTokenPrefix: session.csrfToken
//             ? session.csrfToken.substring(0, 8)
//             : null,
//         },
//         ipAddress,
//         userAgent,
//         severity: 'SECURITY',
//       });
//       throw new ForbiddenException('Invalid CSRF token for session');
//     }

//     return true;
//   }
// }

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
    const cookieToken = req.cookies[CSRF_COOKIE_NAME];
    const sessionId = req.cookies[SESSION_COOKIE_NAME] || req.body?.sessionId;

    const isRefreshEndpoint =
      req.url.endsWith('/refresh') && req.method === 'POST';

    // --- Case 1: Missing tokens (true CSRF failure) ---

    // if (!csrfToken || !cookieToken || !sessionId) {
    //   const hasSessionButMissingCsrf =
    //     sessionId && (!csrfToken || !cookieToken);
    //   const completelyMissingSession = !sessionId;

    //   if (hasSessionButMissingCsrf) {
    //     // This is a REAL CSRF attempt - someone has session but no CSRF protection
    //     await this.eventLogService.logEvent('SECURITY_CSRF_ERROR', {
    //       userId: null,
    //       tenantId: null,
    //       metadata: {
    //         reason: 'missing_csrf_tokens_with_active_session',
    //         hasCsrfToken: !!csrfToken,
    //         hasCookieToken: !!cookieToken,
    //         hasSessionId: !!sessionId,
    //       },
    //       ipAddress,
    //       userAgent,
    //       severity: 'SECURITY',
    //     });
    //     throw new ForbiddenException('Missing CSRF tokens');
    //   }

    //   if (isRefreshEndpoint && completelyMissingSession) {
    //     // Refresh endpoint without session is an auth issue, not CSRF
    //     throw new UnauthorizedException('Session required');
    //   }

    //   // Default case for other endpoints with missing tokens
    //   await this.eventLogService.logEvent('SECURITY_CSRF_ERROR', {
    //     userId: null,
    //     tenantId: null,
    //     metadata: {
    //       reason: 'missing_tokens_or_session',
    //       hasCsrfToken: !!csrfToken,
    //       hasCookieToken: !!cookieToken,
    //       hasSessionId: !!sessionId,
    //     },
    //     ipAddress,
    //     userAgent,
    //     severity: 'SECURITY',
    //   });
    //   throw new ForbiddenException('Missing CSRF token or session');
    // }

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

    // if (!csrfToken || !cookieToken || !sessionId) {
    //   await this.eventLogService.logEvent('SECURITY_CSRF_ERROR', {
    //     userId: null,
    //     tenantId: null,
    //     metadata: {
    //       reason: 'missing_tokens_or_session',
    //       hasCsrfToken: !!csrfToken,
    //       hasCookieToken: !!cookieToken,
    //       hasSessionId: !!sessionId,
    //     },
    //     ipAddress,
    //     userAgent,
    //     severity: 'SECURITY',
    //   });
    //   throw new ForbiddenException('Missing CSRF token or session');
    // }

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
      //       if (isRefreshEndpoint) {
      //         // Let AuthService.refreshTokens handle REFRESH_FAILED/TOKEN_REUSE logging
      //         throw new ForbiddenException('Invalid refresh session or CSRF');
      //       }

      //       // Non-refresh endpoints → still log as CSRF
      //       await this.eventLogService.logEvent('SECURITY_CSRF_MISMATCH', {
      //         userId: session?.userId ?? null,
      //         tenantId: session?.tenantId ?? null,
      //         metadata: {
      //           reason: session ? 'db_vs_cookie_mismatch' : 'session_not_found',
      //           sessionId,
      //         },
      //         ipAddress,
      //         userAgent,
      //         severity: 'SECURITY',
      //       });
      //       throw new ForbiddenException('Invalid CSRF token for session');
      //     }

      //     return true;
      //   }
      // }

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
