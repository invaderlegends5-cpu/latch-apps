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
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ProtectedController = void 0;
const common_1 = require("@nestjs/common");
const jwt_auth_guard_1 = require("../auth/guards/jwt-auth.guard");
const tenant_guard_1 = require("../auth/guards/tenant.guard");
const event_service_1 = require("../events/event.service");
const session_guard_1 = require("../auth/guards/session.guard");
let ProtectedController = class ProtectedController {
    eventLogService;
    constructor(eventLogService) {
        this.eventLogService = eventLogService;
    }
    async me(req, res) {
        res.set({
            'Cache-Control': 'no-store, no-cache, must-revalidate',
            Pragma: 'no-cache',
            Expires: '0',
        });
        await this.eventLogService.logEvent('SENSITIVE_DATA_ACCESSED', {
            userId: req.user.id,
            tenantId: req.user.tenantId,
            metadata: {
                accessedEndpoint: '/protected/me',
                dataType: 'user_profile_and_tenant_info',
                accessType: 'read',
            },
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
        });
        return { ok: true, user: req.user, tenant: req.tenant };
    }
    async getAuditTrail(req) {
        await this.eventLogService.logEvent('AUDIT_TRAIL_ACCESS_ATTEMPTED', {
            userId: req.user.id,
            tenantId: req.user.tenantId,
            metadata: {
                requestedEndpoint: '/protected/audit-trail',
                reason: 'package_does_not_support_audit_trail',
            },
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
        });
        throw new common_1.ForbiddenException('Audit trail functionality is not supported in this package version');
    }
    async exportUserData(req) {
        await this.eventLogService.logEvent('DATA_EXPORT_ATTEMPTED', {
            userId: req.user.id,
            tenantId: req.user.tenantId,
            metadata: {
                requestedAction: 'export_user_data',
                reason: 'package_does_not_support_data_export',
            },
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
        });
        throw new common_1.ForbiddenException('Data export functionality is not supported in this package version');
    }
    async getSecurityStatus(req) {
        await this.eventLogService.logEvent('SECURITY_STATUS_CHECKED', {
            userId: req.user.id,
            tenantId: req.user.tenantId,
            metadata: {
                checkedComponents: [
                    'authentication',
                    'authorization',
                    'session_management',
                ],
            },
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
        });
        return {
            ok: true,
            securityStatus: {
                authentication: 'active',
                authorization: 'enforced',
                sessionManagement: 'secure',
                lastSecurityCheck: new Date(),
            },
        };
    }
    async verifyAuthentication(req) {
        if (!req.user || !req.user.id) {
            await this.eventLogService.logEvent('AUTHENTICATION_VERIFICATION_FAILED', {
                userId: null,
                tenantId: null,
                metadata: {
                    reason: 'missing_user_context',
                    endpoint: '/protected/verify-authentication',
                },
                ipAddress: req.ip,
                userAgent: req.headers['user-agent'],
            });
            throw new common_1.UnauthorizedException('Authentication verification failed - missing user context');
        }
        await this.eventLogService.logEvent('AUTHENTICATION_VERIFIED', {
            userId: req.user.id,
            tenantId: req.user.tenantId,
            metadata: {
                verifiedEndpoint: '/protected/verify-authentication',
            },
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
        });
        return {
            ok: true,
            message: 'Authentication verified successfully',
            user: req.user,
        };
    }
};
exports.ProtectedController = ProtectedController;
__decorate([
    (0, common_1.Get)('me'),
    __param(0, (0, common_1.Req)()),
    __param(1, (0, common_1.Res)({ passthrough: true })),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object]),
    __metadata("design:returntype", Promise)
], ProtectedController.prototype, "me", null);
__decorate([
    (0, common_1.Get)('audit-trail'),
    __param(0, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", Promise)
], ProtectedController.prototype, "getAuditTrail", null);
__decorate([
    (0, common_1.Post)('export-data'),
    __param(0, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", Promise)
], ProtectedController.prototype, "exportUserData", null);
__decorate([
    (0, common_1.Get)('security-status'),
    __param(0, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", Promise)
], ProtectedController.prototype, "getSecurityStatus", null);
__decorate([
    (0, common_1.Get)('verify-authentication'),
    __param(0, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", Promise)
], ProtectedController.prototype, "verifyAuthentication", null);
exports.ProtectedController = ProtectedController = __decorate([
    (0, common_1.Controller)('protected'),
    (0, common_1.UseGuards)(jwt_auth_guard_1.JwtAuthGuard, session_guard_1.SessionGuard, tenant_guard_1.TenantGuard),
    __metadata("design:paramtypes", [event_service_1.EventLogService])
], ProtectedController);
//# sourceMappingURL=protected.controller.js.map