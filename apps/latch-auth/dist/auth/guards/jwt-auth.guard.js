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
exports.JwtAuthGuard = void 0;
const common_1 = require("@nestjs/common");
const passport_1 = require("@nestjs/passport");
const event_service_1 = require("../../events/event.service");
const clear_cookies_unauthorized_exception_1 = require("../exceptions/clear-cookies-unauthorized.exception");
let JwtAuthGuard = class JwtAuthGuard extends (0, passport_1.AuthGuard)('jwt') {
    eventLogService;
    constructor(eventLogService) {
        super();
        this.eventLogService = eventLogService;
    }
    async canActivate(context) {
        const req = context.switchToHttp().getRequest();
        const ipAddress = req.ip;
        const userAgent = req.headers['user-agent'];
        try {
            const result = await super.canActivate(context);
            if (result) {
                return true;
            }
            await this.logAuthFailure(req, null, 'authentication_failed', ipAddress, userAgent);
            throw new clear_cookies_unauthorized_exception_1.ClearCookiesUnauthorizedException('Unauthorized');
        }
        catch (error) {
            await this.logAuthFailure(req, error, 'authentication_error', ipAddress, userAgent);
            throw new clear_cookies_unauthorized_exception_1.ClearCookiesUnauthorizedException('Unauthorized');
        }
    }
    async logAuthFailure(req, error, defaultReason, ipAddress, userAgent) {
        let reason = defaultReason;
        let errorType = null;
        let errorMessage = null;
        if (error && typeof error === 'object') {
            const err = error;
            if (typeof err.name === 'string') {
                errorType = err.name;
                if (err.name === 'JsonWebTokenError') {
                    reason = 'invalid_token';
                }
                else if (err.name === 'TokenExpiredError') {
                    reason = 'token_expired';
                }
            }
            if (typeof err.message === 'string') {
                errorMessage = err.message;
                if (err.message.includes('jwt must be provided')) {
                    reason = 'missing_token';
                }
                else if (err.message.includes('invalid token')) {
                    reason = 'malformed_token';
                }
            }
        }
        let tokenPrefix = null;
        const authHeader = req.headers.authorization;
        if (authHeader &&
            typeof authHeader === 'string' &&
            authHeader.startsWith('Bearer ')) {
            const token = authHeader.substring(7);
            tokenPrefix = token.substring(0, Math.min(20, token.length));
            if (token.length > 20)
                tokenPrefix += '...';
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
};
exports.JwtAuthGuard = JwtAuthGuard;
exports.JwtAuthGuard = JwtAuthGuard = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [event_service_1.EventLogService])
], JwtAuthGuard);
//# sourceMappingURL=jwt-auth.guard.js.map