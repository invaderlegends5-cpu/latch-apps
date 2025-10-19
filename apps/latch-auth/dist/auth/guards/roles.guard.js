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
var RolesGuard_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.RolesGuard = void 0;
const common_1 = require("@nestjs/common");
const core_1 = require("@nestjs/core");
const prisma_service_1 = require("../../prisma/prisma.service");
const event_service_1 = require("../../events/event.service");
const roles_decorator_1 = require("../decorators/roles.decorator");
let RolesGuard = RolesGuard_1 = class RolesGuard {
    reflector;
    prisma;
    eventLog;
    logger = new common_1.Logger(RolesGuard_1.name);
    constructor(reflector, prisma, eventLog) {
        this.reflector = reflector;
        this.prisma = prisma;
        this.eventLog = eventLog;
    }
    async canActivate(context) {
        const requiredRoles = this.reflector.getAllAndOverride(roles_decorator_1.ROLES_KEY, [context.getHandler(), context.getClass()]);
        if (!requiredRoles || requiredRoles.length === 0)
            return true;
        const req = context.switchToHttp().getRequest();
        const user = req.user;
        if (!user || typeof user !== 'object') {
            await this.logDenied(null, null, requiredRoles, 'missing_user_object', req);
            this.logger.warn('RolesGuard: Missing or invalid req.user');
            throw new common_1.ForbiddenException('Not authorized');
        }
        const userId = user.sub ?? user.id;
        const tenantId = user.tenantId ?? user.tenant ?? null;
        if (!userId) {
            await this.logDenied(null, tenantId, requiredRoles, 'missing_user_id', req);
            this.logger.warn('RolesGuard: user object missing id/sub');
            throw new common_1.ForbiddenException('Not authorized');
        }
        const userRoles = await this.prisma.userRole.findMany({
            where: {
                userId,
                ...(tenantId ? { role: { tenantId } } : {}),
            },
            include: { role: true },
        });
        const roleNames = userRoles.map((ur) => ur.role?.name).filter(Boolean);
        const allowed = requiredRoles.some((r) => roleNames.includes(r));
        if (!allowed) {
            await this.logDenied(userId, tenantId, requiredRoles, 'role_mismatch', req);
            this.logger.warn(`RolesGuard denied user=${userId} tenant=${tenantId ?? 'none'} required=${requiredRoles.join(',')}`);
            throw new common_1.ForbiddenException('Insufficient role permissions');
        }
        await this.eventLog.logEvent('ROLE_ACCESS_GRANTED', {
            userId,
            tenantId,
            metadata: {
                requiredRoles,
                grantedRoles: roleNames,
                integrityChain: { enabled: true },
            },
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'] ?? 'unknown',
            severity: 'INFO',
        });
        return true;
    }
    async logDenied(userId, tenantId, requiredRoles, reason, req) {
        try {
            await this.eventLog.logEvent('ROLE_ACCESS_DENIED', {
                userId,
                tenantId,
                metadata: {
                    requiredRoles,
                    reason,
                    integrityChain: { enabled: true },
                },
                ipAddress: req.ip,
                userAgent: req.headers['user-agent'] ?? 'unknown',
                severity: 'SECURITY',
            });
        }
        catch (err) {
            this.logger.error('Failed to log ROLE_ACCESS_DENIED', err);
        }
    }
};
exports.RolesGuard = RolesGuard;
exports.RolesGuard = RolesGuard = RolesGuard_1 = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [core_1.Reflector,
        prisma_service_1.PrismaService,
        event_service_1.EventLogService])
], RolesGuard);
//# sourceMappingURL=roles.guard.js.map