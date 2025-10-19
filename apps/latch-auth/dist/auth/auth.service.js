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
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthService = void 0;
const clear_cookies_unauthorized_exception_1 = require("./exceptions/clear-cookies-unauthorized.exception");
const common_1 = require("@nestjs/common");
const prisma_service_1 = require("../prisma/prisma.service");
const crypto = __importStar(require("crypto"));
const jwt_1 = require("@nestjs/jwt");
const hash_util_1 = require("./utils/hash.util");
const event_service_1 = require("../events/event.service");
function maskPhone(phone) {
    if (!phone)
        return '***';
    if (phone.length <= 4)
        return '***';
    return `${phone.slice(0, 2)}*****${phone.slice(-2)}`;
}
let AuthService = class AuthService {
    prisma;
    jwtService;
    eventLogService;
    constructor(prisma, jwtService, eventLogService) {
        this.prisma = prisma;
        this.jwtService = jwtService;
        this.eventLogService = eventLogService;
    }
    async requestOtp(dto, requestContext) {
        const { phone, tenantSlug } = dto;
        let tenant = await this.prisma.tenant.findUnique({
            where: { slug: tenantSlug ?? 'default' },
        });
        if (!tenant) {
            tenant = await this.prisma.tenant.create({
                data: { name: tenantSlug ?? 'default', slug: tenantSlug ?? 'default' },
            });
        }
        let user = await this.prisma.user.findFirst({
            where: { tenantId: tenant.id, phone },
        });
        if (!user) {
            user = await this.prisma.user.create({
                data: { tenantId: tenant.id, phone },
            });
        }
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        const codeHash = crypto.createHash('sha256').update(code).digest('hex');
        const expiresAt = new Date(Date.now() + 1000 * 60 * 15);
        await this.prisma.oTP.create({
            data: {
                tenantId: tenant.id,
                userId: user.id,
                channel: 'PHONE',
                codeHash,
                expiresAt,
            },
        });
        console.log(`[DEV OTP] ${phone} -> ${code}`);
        await this.eventLogService.logEvent('OTP_REQUEST', {
            userId: user.id,
            tenantId: tenant.id,
            metadata: { phone: maskPhone(phone) },
            ipAddress: requestContext?.ipAddress ?? null,
            userAgent: requestContext?.userAgent ?? null,
            severity: 'INFO',
        });
        return { ok: true, message: 'OTP sent (dev: check server logs)' };
    }
    async verifyOtp(dto, requestContext) {
        const { phone, code, tenantSlug } = dto;
        const tenant = await this.prisma.tenant.findUnique({
            where: { slug: tenantSlug ?? 'default' },
        });
        if (!tenant) {
            await this.eventLogService.logEvent('AUTHENTICATION_VERIFICATION_FAILED', {
                userId: null,
                tenantId: null,
                metadata: { phone, reason: 'tenant_not_found' },
                ipAddress: requestContext?.ipAddress ?? null,
                userAgent: requestContext?.userAgent ?? null,
                severity: 'SECURITY',
            });
            throw new common_1.UnauthorizedException('Tenant not found');
        }
        const user = await this.prisma.user.findFirst({
            where: { tenantId: tenant.id, phone },
        });
        if (!user) {
            await this.eventLogService.logEvent('AUTHENTICATION_VERIFICATION_FAILED', {
                userId: null,
                tenantId: tenant.id,
                metadata: { phone, reason: 'user_not_found' },
                ipAddress: requestContext?.ipAddress ?? null,
                userAgent: requestContext?.userAgent ?? null,
                severity: 'SECURITY',
            });
            throw new common_1.UnauthorizedException('User not found');
        }
        const now = new Date();
        const codeHash = crypto.createHash('sha256').update(code).digest('hex');
        const otp = await this.prisma.oTP.findFirst({
            where: {
                tenantId: tenant.id,
                userId: user.id,
                codeHash,
                consumed: false,
                expiresAt: { gt: now },
            },
            orderBy: { createdAt: 'desc' },
        });
        if (!otp) {
            await this.eventLogService.logEvent('AUTHENTICATION_VERIFICATION_FAILED', {
                userId: user.id,
                tenantId: tenant.id,
                metadata: {
                    phone: maskPhone(phone),
                    reason: 'invalid_or_expired_otp',
                },
                ipAddress: requestContext?.ipAddress ?? null,
                userAgent: requestContext?.userAgent ?? null,
                severity: 'SECURITY',
            });
            throw new common_1.UnauthorizedException('Invalid or expired OTP');
        }
        await this.prisma.oTP.update({
            where: { id: otp.id },
            data: { consumed: true },
        });
        const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 7);
        const nowForSession = new Date();
        const session = await this.prisma.session.create({
            data: {
                userId: user.id,
                tenantId: tenant.id,
                refreshHash: '',
                ipAddress: requestContext?.ipAddress ?? null,
                userAgent: requestContext?.userAgent ?? null,
                lastActiveAt: nowForSession,
                expiresAt,
            },
        });
        const refreshTokenPlain = crypto.randomBytes(40).toString('hex');
        const refreshHash = (0, hash_util_1.hashToken)(refreshTokenPlain);
        await this.prisma.refreshToken.create({
            data: {
                sessionId: session.id,
                tokenHash: refreshHash,
                parentId: null,
                familyId: crypto.randomUUID(),
                revoked: false,
                expiresAt,
            },
        });
        const csrfToken = crypto.randomBytes(16).toString('hex');
        await this.prisma.session.update({
            where: { id: session.id },
            data: {
                refreshHash,
                csrfToken,
            },
        });
        const payload = {
            sub: user.id,
            tenantId: tenant.id,
            sessionId: session.id,
            mfa: false,
        };
        const accessToken = await this.jwtService.signAsync(payload, {
            expiresIn: '15m',
        });
        const activeSessions = await this.getActiveSessionCount(user.id);
        await this.eventLogService.logEvent('LOGIN', {
            userId: user.id,
            tenantId: tenant.id,
            metadata: {
                sessionId: session.id,
                csrfTokenSet: true,
                activeSessions,
            },
            ipAddress: requestContext?.ipAddress ?? null,
            userAgent: requestContext?.userAgent ?? null,
            severity: 'SECURITY',
        });
        return {
            ok: true,
            accessToken,
            refreshToken: refreshTokenPlain,
            sessionId: session.id,
            csrfToken,
            user: { id: user.id, phone: user.phone, tenantId: tenant.id },
        };
    }
    async getUserBySessionId(sessionId, requestContext) {
        const session = await this.prisma.session.findUnique({
            where: { id: sessionId },
            include: { user: true },
        });
        if (!session)
            return null;
        if (session.revoked)
            return null;
        if (session.expiresAt < new Date()) {
            await this.prisma.session.update({
                where: { id: session.id },
                data: { revoked: true },
            });
            await this.eventLogService.logEvent('SESSION_EXPIRED', {
                userId: session.userId,
                tenantId: session.tenantId,
                metadata: { sessionId: session.id },
                ipAddress: requestContext?.ipAddress ?? null,
                userAgent: requestContext?.userAgent ?? null,
                severity: 'SECURITY',
            });
            return null;
        }
        return {
            id: session.user.id,
            tenantId: session.tenantId,
        };
    }
    async refreshTokens(refreshToken, sessionId, requestContext) {
        const hashed = (0, hash_util_1.hashToken)(refreshToken);
        const now = new Date();
        const session = await this.prisma.session.findUnique({
            where: { id: sessionId },
            include: { user: true },
        });
        if (!session) {
            await this.eventLogService.logEvent('REFRESH_FAILED', {
                userId: null,
                tenantId: null,
                metadata: {
                    reason: 'no_session',
                    sessionId,
                },
                ipAddress: requestContext?.ipAddress ?? null,
                userAgent: requestContext?.userAgent ?? null,
                severity: 'SECURITY',
            });
            throw new clear_cookies_unauthorized_exception_1.ClearCookiesUnauthorizedException('Invalid session');
        }
        if (session.revoked) {
            await this.eventLogService.logEvent('REFRESH_FAILED', {
                userId: session.userId,
                tenantId: session.tenantId,
                metadata: {
                    reason: 'revoked',
                    sessionId,
                },
                ipAddress: requestContext?.ipAddress ?? null,
                userAgent: requestContext?.userAgent ?? null,
                severity: 'SECURITY',
            });
            throw new clear_cookies_unauthorized_exception_1.ClearCookiesUnauthorizedException('Session revoked');
        }
        if (session.expiresAt < now) {
            await this.prisma.session.update({
                where: { id: session.id },
                data: { revoked: true },
            });
            await this.eventLogService.logEvent('SESSION_EXPIRED', {
                userId: session.userId,
                tenantId: session.tenantId,
                metadata: { sessionId },
                ipAddress: requestContext?.ipAddress ?? null,
                userAgent: requestContext?.userAgent ?? null,
                severity: 'SECURITY',
            });
            throw new clear_cookies_unauthorized_exception_1.ClearCookiesUnauthorizedException('Session expired');
        }
        let tokenToRevoke = null;
        try {
            tokenToRevoke = await this.prisma.refreshToken.update({
                where: {
                    tokenHash: hashed,
                    sessionId: session.id,
                    revoked: false,
                    expiresAt: { gte: now },
                },
                data: { revoked: true },
                include: { session: true },
            });
        }
        catch (error) {
            const prismaError = error;
            if (prismaError.code === 'P2025') {
                const existingToken = await this.prisma.refreshToken.findUnique({
                    where: { tokenHash: hashed },
                });
                if (existingToken) {
                    if (existingToken.revoked) {
                        await this.handleTokenReuse(existingToken, requestContext);
                        throw new clear_cookies_unauthorized_exception_1.ClearCookiesUnauthorizedException('Refresh token revoked (possible reuse). Session revoked.');
                    }
                    if (existingToken.expiresAt < now) {
                        await this.prisma.session.update({
                            where: { id: session.id },
                            data: { revoked: true },
                        });
                        await this.prisma.refreshToken.updateMany({
                            where: { familyId: existingToken.familyId },
                            data: { revoked: true },
                        });
                        await this.eventLogService.logEvent('REFRESH_FAILED', {
                            userId: session.userId,
                            tenantId: session.tenantId,
                            metadata: {
                                reason: 'token_expired',
                                sessionId,
                                familyId: existingToken.familyId,
                            },
                            ipAddress: requestContext?.ipAddress ?? null,
                            userAgent: requestContext?.userAgent ?? null,
                            severity: 'SECURITY',
                        });
                        throw new clear_cookies_unauthorized_exception_1.ClearCookiesUnauthorizedException('Refresh token expired');
                    }
                    if (existingToken.sessionId !== session.id) {
                        await this.eventLogService.logEvent('REFRESH_FAILED', {
                            userId: session.userId,
                            tenantId: session.tenantId,
                            metadata: {
                                reason: 'token_session_mismatch',
                                tokenSessionId: existingToken.sessionId,
                                sessionId,
                            },
                            ipAddress: requestContext?.ipAddress ?? null,
                            userAgent: requestContext?.userAgent ?? null,
                            severity: 'SECURITY',
                        });
                        throw new clear_cookies_unauthorized_exception_1.ClearCookiesUnauthorizedException('Invalid refresh token for this session');
                    }
                }
                await this.eventLogService.logEvent('REFRESH_FAILED', {
                    userId: session.userId,
                    tenantId: session.tenantId,
                    metadata: { reason: 'token_not_found', sessionId },
                    ipAddress: requestContext?.ipAddress ?? null,
                    userAgent: requestContext?.userAgent ?? null,
                    severity: 'SECURITY',
                });
                throw new clear_cookies_unauthorized_exception_1.ClearCookiesUnauthorizedException('Invalid refresh token');
            }
            throw error;
        }
        const tokenRecord = tokenToRevoke;
        await this.prisma.usedRefreshToken.create({
            data: {
                tokenHash: tokenRecord.tokenHash,
                sessionId: session.id,
                userId: session.userId,
                usedAt: new Date(),
                refreshTokenId: tokenRecord.id,
            },
        });
        const newPlain = crypto.randomBytes(40).toString('hex');
        const newHash = (0, hash_util_1.hashToken)(newPlain);
        const newExpiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 7);
        await this.prisma.refreshToken.create({
            data: {
                sessionId: session.id,
                tokenHash: newHash,
                parentId: tokenRecord.id,
                familyId: tokenRecord.familyId,
                revoked: false,
                expiresAt: newExpiresAt,
            },
        });
        await this.prisma.refreshToken.update({
            where: { id: tokenRecord.id },
            data: { revoked: true },
        });
        const newCsrf = crypto.randomBytes(16).toString('hex');
        await this.prisma.session.update({
            where: { id: session.id },
            data: {
                refreshHash: newHash,
                expiresAt: newExpiresAt,
                csrfToken: newCsrf,
                lastActiveAt: new Date(),
            },
        });
        const payload = {
            sub: session.user.id,
            tenantId: session.tenantId,
            sessionId: session.id,
            mfa: false,
        };
        const accessToken = await this.jwtService.signAsync(payload, {
            expiresIn: '15m',
        });
        const activeSessions = await this.getActiveSessionCount(session.user.id);
        await this.eventLogService.logEvent('REFRESH_SUCCESS', {
            userId: session.user.id,
            tenantId: session.tenantId,
            metadata: {
                sessionId: session.id,
                csrfTokenRotated: true,
                familyId: tokenRecord.familyId,
                activeSessions,
            },
            ipAddress: requestContext?.ipAddress ?? null,
            userAgent: requestContext?.userAgent ?? null,
            severity: 'INFO',
        });
        return {
            ok: true,
            accessToken,
            refreshToken: newPlain,
            sessionId: session.id,
            csrfToken: newCsrf,
            familyId: tokenRecord.familyId,
            user: {
                id: session.user.id,
                phone: session.user.phone,
                tenantId: session.tenantId,
            },
        };
    }
    async handleTokenReuse(tokenRecord, requestContext) {
        const familyId = tokenRecord.familyId;
        await this.prisma.refreshToken.updateMany({
            where: { familyId },
            data: { revoked: true },
        });
        const session = await this.prisma.session.update({
            where: { id: tokenRecord.sessionId },
            data: { revoked: true },
        });
        try {
            await this.prisma.usedRefreshToken.create({
                data: {
                    tokenHash: tokenRecord.tokenHash,
                    sessionId: tokenRecord.sessionId,
                    userId: session.userId,
                    usedAt: new Date(),
                    refreshTokenId: tokenRecord.id,
                },
            });
        }
        catch (err) {
            if (err.code !== 'P2002')
                throw err;
        }
        await this.eventLogService.logEvent('TOKEN_REUSE', {
            userId: session.userId,
            tenantId: session.tenantId,
            metadata: {
                familyId,
                tokenId: tokenRecord.id,
                sessionId: tokenRecord.sessionId,
                reason: 'token_reuse_detected',
            },
            ipAddress: requestContext?.ipAddress ?? null,
            userAgent: requestContext?.userAgent ?? null,
            severity: 'SECURITY',
        });
        console.warn('[SECURITY] TOKEN_REUSE detected', {
            familyId,
            tokenId: tokenRecord.id,
            sessionId: tokenRecord.sessionId,
            ...(requestContext && {
                ip: requestContext.ipAddress,
                ua: requestContext.userAgent,
            }),
        });
    }
    async getActiveSessionCount(userId) {
        return this.prisma.session.count({
            where: {
                userId,
                revoked: false,
                expiresAt: { gt: new Date() },
            },
        });
    }
    async revokeSession(sessionId, requestContext) {
        await this.prisma.session.updateMany({
            where: { id: sessionId },
            data: { revoked: true },
        });
        await this.prisma.refreshToken.updateMany({
            where: { sessionId },
            data: { revoked: true },
        });
        let userId = null;
        let tenantId = null;
        const sessionUser = await this.getUserBySessionId(sessionId);
        if (sessionUser) {
            userId = sessionUser.id;
            tenantId = sessionUser.tenantId;
        }
        await this.eventLogService.logEvent('SESSION_REVOKE', {
            userId,
            tenantId,
            metadata: { sessionId },
            ipAddress: requestContext?.ipAddress ?? null,
            userAgent: requestContext?.userAgent ?? null,
            severity: 'INFO',
        });
        return { ok: true };
    }
    async revokeAllSessionsForUser(userId, requestContext) {
        const sessions = await this.prisma.session.findMany({
            where: { userId },
            include: { user: true },
        });
        if (sessions.length === 0)
            return 0;
        await this.prisma.$transaction([
            this.prisma.session.updateMany({
                where: { userId },
                data: { revoked: true },
            }),
            this.prisma.refreshToken.updateMany({
                where: { sessionId: { in: sessions.map((s) => s.id) } },
                data: { revoked: true },
            }),
        ]);
        for (const session of sessions) {
            await this.eventLogService.logEvent('SESSION_REVOKE', {
                userId: session.userId,
                tenantId: session.tenantId,
                metadata: {
                    sessionId: session.id,
                    reason: 'revoke_all',
                },
                ipAddress: requestContext?.ipAddress ?? null,
                userAgent: requestContext?.userAgent ?? null,
                severity: 'INFO',
            });
        }
        await this.eventLogService.logEvent('SESSION_REVOKE_ALL', {
            userId,
            tenantId: sessions[0]?.tenantId || null,
            metadata: {
                reason: 'revoke_all_sessions',
                revokedCount: sessions.length,
                activeSessionsAfter: 0,
            },
            ipAddress: requestContext?.ipAddress ?? null,
            userAgent: requestContext?.userAgent ?? null,
            severity: 'INFO',
        });
        return sessions.length;
    }
};
exports.AuthService = AuthService;
exports.AuthService = AuthService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [prisma_service_1.PrismaService,
        jwt_1.JwtService,
        event_service_1.EventLogService])
], AuthService);
//# sourceMappingURL=auth.service.js.map