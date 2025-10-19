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
var SecurityController_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.SecurityController = void 0;
const common_1 = require("@nestjs/common");
const jwt_auth_guard_1 = require("../auth/guards/jwt-auth.guard");
const tenant_guard_1 = require("../auth/guards/tenant.guard");
const roles_guard_1 = require("../auth/guards/roles.guard");
const admin_only_decorator_1 = require("../auth/decorators/admin-only.decorator");
const security_monitor_service_1 = require("./security-monitor.service");
const event_service_1 = require("../events/event.service");
let SecurityController = SecurityController_1 = class SecurityController {
    monitor;
    eventLog;
    logger = new common_1.Logger(SecurityController_1.name);
    constructor(monitor, eventLog) {
        this.monitor = monitor;
        this.eventLog = eventLog;
    }
    async getSecurityStatus() {
        try {
            const threatSummary = typeof this.monitor.getSecurityStatus === 'function'
                ? this.monitor.getSecurityStatus()
                : { info: 'monitor.getSecurityStatus() not available' };
            let chainResult;
            try {
                chainResult = await this.eventLog.verifyChain();
            }
            catch (err) {
                chainResult = {
                    valid: false,
                    error: err.message || 'Unknown error',
                };
            }
            const from = new Date(Date.now() - 60 * 60 * 1000).toISOString();
            const eventTypesToReport = [
                'TOKEN_REUSE',
                'SECURITY_CSRF_MISMATCH',
                'AUTH_JWT_FAILURE',
                'REFRESH_FAILED',
                'OTP_FAILED',
            ];
            const recentCounts = {};
            for (const t of eventTypesToReport) {
                try {
                    const paginated = await this.eventLog.findByType(t, 1, 0, from);
                    recentCounts[t] = paginated.meta?.total ?? null;
                }
                catch (err) {
                    this.logger.warn(`Failed to count events for ${t}`, err.message);
                    recentCounts[t] = null;
                }
            }
            const chain = 'error' in chainResult
                ? {
                    valid: chainResult.valid,
                    total: null,
                    brokenIndex: null,
                    error: chainResult.error,
                }
                : 'brokenIndex' in chainResult
                    ? {
                        valid: chainResult.valid,
                        total: chainResult.total,
                        brokenIndex: chainResult.brokenIndex,
                        error: null,
                    }
                    : {
                        valid: chainResult.valid,
                        total: chainResult.total,
                        brokenIndex: null,
                        error: null,
                    };
            return {
                ok: true,
                timestamp: new Date().toISOString(),
                threatSummary,
                chain,
                recentCounts,
            };
        }
        catch (err) {
            this.logger.error('getSecurityStatus failed', err);
            return {
                ok: false,
                error: err.message ?? String(err),
            };
        }
    }
};
exports.SecurityController = SecurityController;
__decorate([
    (0, common_1.Get)('status'),
    (0, admin_only_decorator_1.AdminOnly)(),
    (0, common_1.HttpCode)(common_1.HttpStatus.OK),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", Promise)
], SecurityController.prototype, "getSecurityStatus", null);
exports.SecurityController = SecurityController = SecurityController_1 = __decorate([
    (0, common_1.Controller)('v1/security'),
    (0, common_1.UseGuards)(jwt_auth_guard_1.JwtAuthGuard, tenant_guard_1.TenantGuard, roles_guard_1.RolesGuard),
    __metadata("design:paramtypes", [security_monitor_service_1.SecurityMonitoringService,
        event_service_1.EventLogService])
], SecurityController);
//# sourceMappingURL=security.controller.js.map