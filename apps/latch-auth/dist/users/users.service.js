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
exports.UsersService = void 0;
const common_1 = require("@nestjs/common");
const prisma_service_1 = require("../prisma/prisma.service");
const event_service_1 = require("../events/event.service");
let UsersService = class UsersService {
    prisma;
    eventLogService;
    constructor(prisma, eventLogService) {
        this.prisma = prisma;
        this.eventLogService = eventLogService;
    }
    async findById(id) {
        return this.prisma.user.findUnique({ where: { id } });
    }
    async findByIdWithAccessCheck(requestingUserId, targetUserId, tenantId, ipAddress, userAgent) {
        if (requestingUserId !== targetUserId) {
            await this.eventLogService.logEvent('USER_DATA_ACCESS_ATTEMPT', {
                userId: requestingUserId,
                tenantId,
                metadata: {
                    targetUserId,
                    reason: 'cross_user_access',
                },
                ipAddress,
                userAgent,
            });
            throw new common_1.UnauthorizedException('Access denied');
        }
        const user = await this.prisma.user.findUnique({
            where: { id: targetUserId, tenantId },
        });
        if (user) {
            await this.eventLogService.logEvent('USER_DATA_ACCESSED', {
                userId: requestingUserId,
                tenantId,
                metadata: {
                    targetUserId,
                    accessType: 'self_access',
                },
                ipAddress,
                userAgent,
            });
        }
        return user;
    }
    async listForTenant(requestingUserId, tenantId, ipAddress, userAgent) {
        await this.eventLogService.logEvent('USER_LIST_ACCESSED', {
            userId: requestingUserId,
            tenantId,
            metadata: {
                action: 'list_users_for_tenant',
            },
            ipAddress,
            userAgent,
        });
        const requestingUser = await this.prisma.user.findUnique({
            where: { id: requestingUserId, tenantId },
        });
        if (!requestingUser) {
            await this.eventLogService.logEvent('USER_LIST_ACCESS_DENIED', {
                userId: requestingUserId,
                tenantId,
                metadata: {
                    reason: 'user_not_in_tenant',
                },
                ipAddress,
                userAgent,
            });
            throw new common_1.UnauthorizedException('User does not belong to this tenant');
        }
        return this.prisma.user.findMany({
            where: { tenantId },
            select: {
                id: true,
                phone: true,
            },
        });
    }
    async updateProfile(userId, tenantId, updates, ipAddress, userAgent) {
        if (updates.phone) {
            if (!/^\+?[1-9]\d{1,14}$/.test(updates.phone)) {
                await this.eventLogService.logEvent('USER_PROFILE_UPDATE_FAILED', {
                    userId,
                    tenantId,
                    metadata: {
                        reason: 'invalid_phone_format',
                        attemptedField: 'phone',
                    },
                    ipAddress,
                    userAgent,
                });
                throw new common_1.UnauthorizedException('Invalid phone number format');
            }
        }
        await this.eventLogService.logEvent('USER_PROFILE_UPDATE', {
            userId,
            tenantId,
            metadata: {
                updatedFields: Object.keys(updates),
            },
            ipAddress,
            userAgent,
        });
        return this.prisma.user.update({
            where: { id: userId, tenantId },
            data: updates,
        });
    }
};
exports.UsersService = UsersService;
exports.UsersService = UsersService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [prisma_service_1.PrismaService,
        event_service_1.EventLogService])
], UsersService);
//# sourceMappingURL=users.service.js.map