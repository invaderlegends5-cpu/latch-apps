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
exports.JwtStrategy = void 0;
const common_1 = require("@nestjs/common");
const passport_1 = require("@nestjs/passport");
const passport_jwt_1 = require("passport-jwt");
const prisma_service_1 = require("../prisma/prisma.service");
const event_service_1 = require("../events/event.service");
let JwtStrategy = class JwtStrategy extends (0, passport_1.PassportStrategy)(passport_jwt_1.Strategy, 'jwt') {
    prisma;
    eventLogService;
    constructor(prisma, eventLogService) {
        super({
            jwtFromRequest: passport_jwt_1.ExtractJwt.fromAuthHeaderAsBearerToken(),
            ignoreExpiration: false,
            secretOrKey: process.env.JWT_SECRET ?? 'dev_jwt_secret_change_me',
        });
        this.prisma = prisma;
        this.eventLogService = eventLogService;
    }
    async validate(payload) {
        if (!payload || !payload.sub) {
            await this.eventLogService.logEvent('AUTH_JWT_FAILURE', {
                userId: null,
                tenantId: null,
                metadata: {
                    reason: 'malformed_token',
                    payloadKeys: Object.keys(payload || {}),
                },
                severity: 'SECURITY',
            });
            throw new common_1.UnauthorizedException('Invalid token');
        }
        if (!payload.sessionId) {
            await this.eventLogService.logEvent('AUTH_JWT_FAILURE', {
                userId: payload.sub,
                tenantId: payload.tenantId ?? null,
                metadata: { reason: 'missing_sessionId_in_token' },
                severity: 'SECURITY',
            });
            throw new common_1.UnauthorizedException('Invalid token (no session)');
        }
        const session = await this.prisma.session.findUnique({
            where: { id: payload.sessionId },
            include: { user: true },
        });
        const now = new Date();
        if (!session) {
            await this.eventLogService.logEvent('AUTH_JWT_FAILURE', {
                userId: payload.sub,
                tenantId: payload.tenantId ?? null,
                metadata: { reason: 'session_not_found', sessionId: payload.sessionId },
                severity: 'SECURITY',
            });
            throw new common_1.UnauthorizedException('Session not found');
        }
        if (session.revoked) {
            await this.eventLogService.logEvent('AUTH_JWT_FAILURE', {
                userId: session.userId,
                tenantId: session.tenantId,
                metadata: { reason: 'session_revoked', sessionId: session.id },
                severity: 'SECURITY',
            });
            throw new common_1.UnauthorizedException('Session revoked');
        }
        if (session.expiresAt < now) {
            await this.prisma.session.update({
                where: { id: session.id },
                data: { revoked: true },
            });
            await this.eventLogService.logEvent('SESSION_EXPIRED', {
                userId: session.userId,
                tenantId: session.tenantId,
                metadata: { sessionId: session.id },
                severity: 'SECURITY',
            });
            throw new common_1.UnauthorizedException('Session expired');
        }
        return {
            sub: payload.sub,
            tenantId: payload.tenantId,
            sessionId: payload.sessionId,
            mfa: payload.mfa ?? false,
        };
    }
};
exports.JwtStrategy = JwtStrategy;
exports.JwtStrategy = JwtStrategy = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [prisma_service_1.PrismaService,
        event_service_1.EventLogService])
], JwtStrategy);
//# sourceMappingURL=jwt.strategy.js.map