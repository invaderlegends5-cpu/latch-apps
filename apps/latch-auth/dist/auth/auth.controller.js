"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthController = void 0;
const throttler_1 = require("@nestjs/throttler");
const clear_cookies_unauthorized_exception_1 = require("./exceptions/clear-cookies-unauthorized.exception");
const common_1 = require("@nestjs/common");
const express_1 = __importDefault(require("express"));
const auth_service_1 = require("./auth.service");
const request_otp_dto_1 = require("./dto/request-otp.dto");
const verify_otp_dto_1 = require("./dto/verify-otp.dto");
const cookie_util_1 = require("./utils/cookie.util");
const jwt_auth_guard_1 = require("./guards/jwt-auth.guard");
const tenant_guard_1 = require("./guards/tenant.guard");
const csrf_guard_1 = require("./guards/csrf.guard");
const authTypes = __importStar(require("./types/auth.types"));
const event_service_1 = require("../events/event.service");
const session_guard_1 = require("./guards/session.guard");
let AuthController = class AuthController {
    auth;
    eventLogService;
    constructor(auth, eventLogService) {
        this.auth = auth;
        this.eventLogService = eventLogService;
    }
    async requestOtp(dto, req) {
        return this.auth.requestOtp(dto, {
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'] || null,
        });
    }
    async verifyOtp(dto, req, res) {
        const result = await this.auth.verifyOtp(dto, {
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'] || null,
        });
        (0, cookie_util_1.setRefreshCookies)(res, result.refreshToken, result.sessionId, result.csrfToken);
        return result;
    }
    async refresh(req, res) {
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
                userAgent: req.headers['user-agent'] || null,
                severity: 'SECURITY',
            });
            throw new common_1.UnauthorizedException('Missing cookies');
        }
        try {
            const result = await this.auth.refreshTokens(refresh, sessionId, {
                ipAddress: req.ip,
                userAgent: req.headers['user-agent'] || null,
            });
            (0, cookie_util_1.setRefreshCookies)(res, result.refreshToken, result.sessionId, result.csrfToken);
            return result;
        }
        catch (error) {
            if (error instanceof clear_cookies_unauthorized_exception_1.ClearCookiesUnauthorizedException) {
                (0, cookie_util_1.clearRefreshCookies)(res);
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
                userAgent: req.headers['user-agent'] || null,
                severity: 'SECURITY',
            });
            throw error;
        }
    }
    async logout(req, res) {
        const sessionId = req.cookies['latch_session'];
        let userId = null;
        let tenantId = null;
        let activeSessionsBefore = 0;
        if (sessionId) {
            const sessionUser = await this.auth.getUserBySessionId(sessionId, {
                ipAddress: req.ip,
                userAgent: req.headers['user-agent'] || null,
            });
            if (sessionUser) {
                userId = sessionUser.id;
                tenantId = sessionUser.tenantId;
                activeSessionsBefore = await this.auth.getActiveSessionCount(userId);
                await this.auth.revokeSession(sessionId, {
                    ipAddress: req.ip,
                    userAgent: req.headers['user-agent'] || null,
                });
            }
            else {
                await this.eventLogService.logEvent('LOGOUT_ATTEMPT_INVALID', {
                    userId: null,
                    tenantId: null,
                    metadata: { sessionId, reason: 'session_not_found_or_expired' },
                    ipAddress: req.ip,
                    userAgent: req.headers['user-agent'] || null,
                    severity: 'SECURITY',
                });
                await this.eventLogService.logEvent('LOGOUT_ATTEMPT_INVALID', {
                    userId: null,
                    tenantId: null,
                    metadata: { sessionId, reason: 'session_not_found_or_expired' },
                    ipAddress: req.ip,
                    userAgent: req.headers['user-agent'] || null,
                    severity: 'SECURITY',
                });
            }
        }
        (0, cookie_util_1.clearRefreshCookies)(res);
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
            userAgent: req.headers['user-agent'] || null,
            severity: 'INFO',
        });
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
            userAgent: req.headers['user-agent'] || null,
            severity: 'INFO',
        });
        return { ok: true };
    }
    async revokeAll(req, res) {
        const revokedCount = await this.auth.revokeAllSessionsForUser(req.user.id, {
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'] || null,
        });
        (0, cookie_util_1.clearRefreshCookies)(res);
        return { ok: true, revokedCount };
    }
};
exports.AuthController = AuthController;
__decorate([
    (0, common_1.Post)('request-otp'),
    (0, throttler_1.Throttle)({ otpRequest: { limit: 3, ttl: 300 } }),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [request_otp_dto_1.RequestOtpDto, Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "requestOtp", null);
__decorate([
    (0, common_1.Post)('otpVerify'),
    (0, throttler_1.Throttle)({ otpVerify: { limit: 6, ttl: 600 } }),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, common_1.Req)()),
    __param(2, (0, common_1.Res)({ passthrough: true })),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [verify_otp_dto_1.VerifyOtpDto, Object, Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "verifyOtp", null);
__decorate([
    (0, common_1.UseGuards)(csrf_guard_1.CsrfGuard),
    (0, common_1.Post)('refresh'),
    (0, throttler_1.Throttle)({ refrish: { limit: 20, ttl: 60 } }),
    __param(0, (0, common_1.Req)()),
    __param(1, (0, common_1.Res)({ passthrough: true })),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "refresh", null);
__decorate([
    (0, common_1.UseGuards)(tenant_guard_1.TenantGuard, csrf_guard_1.CsrfGuard),
    (0, common_1.Post)('logout'),
    __param(0, (0, common_1.Req)()),
    __param(1, (0, common_1.Res)({ passthrough: true })),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "logout", null);
__decorate([
    (0, common_1.UseGuards)(jwt_auth_guard_1.JwtAuthGuard, session_guard_1.SessionGuard, tenant_guard_1.TenantGuard, csrf_guard_1.CsrfGuard),
    (0, common_1.Post)('revoke-all'),
    __param(0, (0, common_1.Req)()),
    __param(1, (0, common_1.Res)({ passthrough: true })),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "revokeAll", null);
exports.AuthController = AuthController = __decorate([
    (0, common_1.Controller)('auth'),
    __metadata("design:paramtypes", [auth_service_1.AuthService,
        event_service_1.EventLogService])
], AuthController);
//# sourceMappingURL=auth.controller.js.map