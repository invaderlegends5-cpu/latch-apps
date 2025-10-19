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
exports.TenantGuard = void 0;
const common_1 = require("@nestjs/common");
const prisma_service_1 = require("../../prisma/prisma.service");
const event_service_1 = require("../../events/event.service");
function isRecord(value) {
    return value !== null && typeof value === 'object';
}
function extractTenantSlugFromHeaders(headers) {
    const headerValue = headers['x-tenant-slug'];
    if (typeof headerValue === 'string') {
        return headerValue;
    }
    if (Array.isArray(headerValue) && headerValue.length > 0) {
        return String(headerValue[0]);
    }
    return null;
}
function extractTenantSlugFromBody(body) {
    if (isRecord(body) && 'tenantSlug' in body) {
        const slug = body.tenantSlug;
        if (typeof slug === 'string') {
            return slug;
        }
    }
    return null;
}
function extractTenantSlugFromQuery(query) {
    if (isRecord(query) && 'tenantSlug' in query) {
        const slug = query.tenantSlug;
        if (typeof slug === 'string') {
            return slug;
        }
        if (Array.isArray(slug) && slug.length > 0) {
            return String(slug[0]);
        }
    }
    return null;
}
let TenantGuard = class TenantGuard {
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
        const tenantSlug = extractTenantSlugFromHeaders(req.headers) ||
            extractTenantSlugFromBody(req.body) ||
            extractTenantSlugFromQuery(req.query);
        if (!tenantSlug) {
            await this.eventLogService.logEvent('TENANT_VALIDATION_ERROR', {
                userId: req.user?.id || null,
                tenantId: req.user?.tenantId || null,
                metadata: {
                    reason: 'tenant_not_provided',
                },
                ipAddress,
                userAgent,
                severity: 'SECURITY',
            });
            throw new common_1.ForbiddenException('Tenant not provided');
        }
        if (!/^[a-zA-Z0-9-_]+$/.test(tenantSlug)) {
            await this.eventLogService.logEvent('TENANT_VALIDATION_ERROR', {
                userId: req.user?.id || null,
                tenantId: req.user?.tenantId || null,
                metadata: {
                    reason: 'invalid_tenant_slug_format',
                    tenantSlug: tenantSlug.substring(0, 50),
                },
                ipAddress,
                userAgent,
                severity: 'SECURITY',
            });
            throw new common_1.ForbiddenException('Invalid tenant slug format');
        }
        const tenant = await this.prisma.tenant.findUnique({
            where: { slug: tenantSlug },
        });
        if (!tenant) {
            await this.eventLogService.logEvent('TENANT_VALIDATION_ERROR', {
                userId: req.user?.id || null,
                tenantId: req.user?.tenantId || null,
                metadata: {
                    reason: 'tenant_not_found',
                    tenantSlug: tenantSlug.substring(0, 50),
                },
                ipAddress,
                userAgent,
                severity: 'SECURITY',
            });
            throw new common_1.ForbiddenException('Tenant not found');
        }
        req.tenant = tenant;
        if (req.user?.tenantId && req.user.tenantId !== tenant.id) {
            await this.eventLogService.logEvent('TENANT_MISMATCH', {
                userId: req.user.id,
                tenantId: req.user.tenantId,
                metadata: {
                    reason: 'tenant_mismatch',
                    requestedTenantId: tenant.id,
                    requestedTenantSlug: tenantSlug.substring(0, 50),
                    userTenantId: req.user.tenantId,
                },
                ipAddress,
                userAgent,
                severity: 'SECURITY',
            });
            throw new common_1.ForbiddenException('Tenant mismatch');
        }
        return true;
    }
};
exports.TenantGuard = TenantGuard;
exports.TenantGuard = TenantGuard = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [prisma_service_1.PrismaService,
        event_service_1.EventLogService])
], TenantGuard);
//# sourceMappingURL=tenant.guard.js.map