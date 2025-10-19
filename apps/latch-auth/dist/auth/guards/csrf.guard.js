"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.CsrfGuard = void 0;
const common_1 = require("@nestjs/common");
const prisma_service_1 = require("../../prisma/prisma.service");
const cookie_util_1 = require("../utils/cookie.util");
const event_service_1 = require("../../events/event.service");
let CsrfGuard = class CsrfGuard {
    prisma;
    eventLogService;
    constructor(prisma, eventLogService) {
        this.prisma = prisma;
        this.eventLogService = eventLogService;
    }
    async canActivate(context) {
        const req = context.switchToHttp().getRequest();
        const ipAddress = req.ip;
        const userAgent = req.headers['user-agent'];
        const rawHeaderToken = req.headers['x-csrf-token'];
        const rawXsrfToken = req.headers['x-xsrf-token'];
        let headerToken;
        let xsrfToken;
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
                throw new common_1.ForbiddenException('Multiple CSRF tokens not allowed');
            }
            headerToken = rawHeaderToken[0];
        }
        else if (rawHeaderToken) {
            headerToken = String(rawHeaderToken);
        }
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
                throw new common_1.ForbiddenException('Multiple XSRF tokens not allowed');
            }
            xsrfToken = rawXsrfToken[0];
        }
        else if (rawXsrfToken) {
            xsrfToken = String(rawXsrfToken);
        }
        const csrfToken = headerToken || xsrfToken;
        const cookieToken = req.cookies[cookie_util_1.CSRF_COOKIE_NAME];
        const sessionId = req.cookies[cookie_util_1.SESSION_COOKIE_NAME] || req.body?.sessionId;
        const isRefreshEndpoint = req.url.endsWith('/refresh') && req.method === 'POST';
        if (!csrfToken || !cookieToken || !sessionId) {
            const hasSessionButMissingCsrf = sessionId && (!csrfToken || !cookieToken);
            const completelyMissingSession = !sessionId;
            if (isRefreshEndpoint) {
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
                throw new common_1.UnauthorizedException('Invalid refresh attempt');
            }
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
            throw new common_1.ForbiddenException('Missing CSRF token or session');
        }
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
            throw new common_1.ForbiddenException('Invalid CSRF token format');
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
            throw new common_1.ForbiddenException('Invalid CSRF cookie token format');
        }
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
            throw new common_1.ForbiddenException('CSRF token mismatch (header vs cookie)');
        }
        const session = await this.prisma.session.findUnique({
            where: { id: sessionId },
        });
        if (!session ||
            session.revoked ||
            !session.csrfToken ||
            session.csrfToken !== cookieToken) {
            if (isRefreshEndpoint) {
                if (!session) {
                    throw new common_1.UnauthorizedException('Session not found');
                }
                else if (session.revoked) {
                    throw new common_1.UnauthorizedException('Session revoked');
                }
                else if (!session.csrfToken || session.csrfToken !== cookieToken) {
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
                    throw new common_1.ForbiddenException('Invalid CSRF token for session');
                }
            }
            else {
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
                throw new common_1.ForbiddenException('Invalid CSRF token for session');
            }
        }
        return true;
    }
};
exports.CsrfGuard = CsrfGuard;
exports.CsrfGuard = CsrfGuard = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [prisma_service_1.PrismaService,
        event_service_1.EventLogService])
], CsrfGuard);
//# sourceMappingURL=csrf.guard.js.map