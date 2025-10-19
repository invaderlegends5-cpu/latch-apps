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
var SessionCleanerService_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.SessionCleanerService = void 0;
const common_1 = require("@nestjs/common");
const schedule_1 = require("@nestjs/schedule");
const prisma_service_1 = require("../prisma/prisma.service");
const event_service_1 = require("../events/event.service");
const security_config_1 = require("../config/security.config");
let SessionCleanerService = SessionCleanerService_1 = class SessionCleanerService {
    prisma;
    eventLogService;
    logger = new common_1.Logger(SessionCleanerService_1.name);
    constructor(prisma, eventLogService) {
        this.prisma = prisma;
        this.eventLogService = eventLogService;
    }
    async pruneExpiredSessions() {
        const now = new Date();
        const retentionMs = security_config_1.SecurityConfig.REFRESH_TOKEN_RETENTION_DAYS * 24 * 60 * 60 * 1000;
        this.logger.debug('Running scheduled session and token cleanup');
        const expiredSessions = await this.prisma.session.updateMany({
            where: { expiresAt: { lt: now }, revoked: false },
            data: { revoked: true },
        });
        if (expiredSessions.count > 0) {
            await this.eventLogService.logEvent('SESSION_REVOKE_ALL', {
                userId: null,
                tenantId: null,
                metadata: {
                    reason: 'scheduled_prune',
                    revokedCount: expiredSessions.count,
                },
                severity: 'INFO',
            });
        }
        const deletedTokens = await this.prisma.usedRefreshToken.deleteMany({
            where: { usedAt: { lt: new Date(Date.now() - retentionMs) } },
        });
        if (deletedTokens.count > 0) {
            await this.eventLogService.logEvent('USED_REFRESH_TOKEN_PURGE', {
                userId: null,
                tenantId: null,
                metadata: {
                    reason: 'retention_expired',
                    deletedCount: deletedTokens.count,
                    retentionDays: security_config_1.SecurityConfig.REFRESH_TOKEN_RETENTION_DAYS,
                },
                severity: 'INFO',
            });
        }
        this.logger.debug(`Cleanup complete: ${expiredSessions.count} expired sessions revoked, ${deletedTokens.count} old refresh tokens purged.`);
    }
};
exports.SessionCleanerService = SessionCleanerService;
__decorate([
    (0, schedule_1.Cron)(security_config_1.SecurityConfig.CLEANUP_CRON_EXPRESSION),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", Promise)
], SessionCleanerService.prototype, "pruneExpiredSessions", null);
exports.SessionCleanerService = SessionCleanerService = SessionCleanerService_1 = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [prisma_service_1.PrismaService,
        event_service_1.EventLogService])
], SessionCleanerService);
//# sourceMappingURL=session-cleaner.service.js.map