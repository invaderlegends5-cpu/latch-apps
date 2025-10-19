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
exports.EventController = void 0;
const common_1 = require("@nestjs/common");
const cache_control_interceptor_1 = require("../interceptors/cache-control.interceptor");
const event_service_1 = require("./event.service");
const jwt_auth_guard_1 = require("../auth/guards/jwt-auth.guard");
const tenant_guard_1 = require("../auth/guards/tenant.guard");
const client_1 = require("@prisma/client");
const session_guard_1 = require("../auth/guards/session.guard");
let EventController = class EventController {
    eventLog;
    constructor(eventLog) {
        this.eventLog = eventLog;
    }
    async recent(res, limit = 50, offset = 0, from, to) {
        const parsedLimit = Number(limit);
        const parsedOffset = Number(offset);
        if (isNaN(parsedLimit) || parsedLimit < 1 || parsedLimit > 1000) {
            throw new common_1.BadRequestException('Limit must be a number between 1 and 1000');
        }
        if (isNaN(parsedOffset) || parsedOffset < 0) {
            throw new common_1.BadRequestException('Offset must be a non-negative number');
        }
        let parsedFrom;
        let parsedTo;
        if (from) {
            parsedFrom = new Date(from);
            if (isNaN(parsedFrom.getTime())) {
                throw new common_1.BadRequestException('Invalid from date format');
            }
        }
        if (to) {
            parsedTo = new Date(to);
            if (isNaN(parsedTo.getTime())) {
                throw new common_1.BadRequestException('Invalid to date format');
            }
        }
        return this.eventLog.findRecent(parsedLimit, parsedOffset, parsedFrom?.toISOString(), parsedTo?.toISOString());
    }
    async byType(res, type, limit = 50, offset = 0, from, to) {
        const parsedLimit = Number(limit);
        const parsedOffset = Number(offset);
        if (isNaN(parsedLimit) || parsedLimit < 1 || parsedLimit > 1000) {
            throw new common_1.BadRequestException('Limit must be a number between 1 and 1000');
        }
        if (isNaN(parsedOffset) || parsedOffset < 0) {
            throw new common_1.BadRequestException('Offset must be a non-negative number');
        }
        if (!type) {
            throw new common_1.BadRequestException('Event type is required');
        }
        const isValidType = (value) => {
            return Object.values(client_1.$Enums.EventType).includes(value);
        };
        if (!isValidType(type)) {
            throw new common_1.BadRequestException(`Invalid event type: ${type}`);
        }
        let parsedFrom;
        let parsedTo;
        if (from) {
            parsedFrom = new Date(from);
            if (isNaN(parsedFrom.getTime())) {
                throw new common_1.BadRequestException('Invalid from date format');
            }
        }
        if (to) {
            parsedTo = new Date(to);
            if (isNaN(parsedTo.getTime())) {
                throw new common_1.BadRequestException('Invalid to date format');
            }
        }
        return this.eventLog.findByType(type, parsedLimit, parsedOffset, parsedFrom?.toISOString(), parsedTo?.toISOString());
    }
    async byUser(res, userId, limit = 50, offset = 0, from, to) {
        const parsedLimit = Number(limit);
        const parsedOffset = Number(offset);
        if (isNaN(parsedLimit) || parsedLimit < 1 || parsedLimit > 1000) {
            throw new common_1.BadRequestException('Limit must be a number between 1 and 1000');
        }
        if (isNaN(parsedOffset) || parsedOffset < 0) {
            throw new common_1.BadRequestException('Offset must be a non-negative number');
        }
        if (!userId) {
            throw new common_1.BadRequestException('User ID is required');
        }
        let parsedFrom;
        let parsedTo;
        if (from) {
            parsedFrom = new Date(from);
            if (isNaN(parsedFrom.getTime())) {
                throw new common_1.BadRequestException('Invalid from date format');
            }
        }
        if (to) {
            parsedTo = new Date(to);
            if (isNaN(parsedTo.getTime())) {
                throw new common_1.BadRequestException('Invalid to date format');
            }
        }
        return this.eventLog.findByUser(userId, parsedLimit, parsedOffset, parsedFrom?.toISOString(), parsedTo?.toISOString());
    }
};
exports.EventController = EventController;
__decorate([
    (0, common_1.Get)('recent'),
    __param(0, (0, common_1.Res)({ passthrough: true })),
    __param(1, (0, common_1.Query)('limit')),
    __param(2, (0, common_1.Query)('offset')),
    __param(3, (0, common_1.Query)('from')),
    __param(4, (0, common_1.Query)('to')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object, Object, String, String]),
    __metadata("design:returntype", Promise)
], EventController.prototype, "recent", null);
__decorate([
    (0, common_1.Get)('type'),
    __param(0, (0, common_1.Res)({ passthrough: true })),
    __param(1, (0, common_1.Query)('type')),
    __param(2, (0, common_1.Query)('limit')),
    __param(3, (0, common_1.Query)('offset')),
    __param(4, (0, common_1.Query)('from')),
    __param(5, (0, common_1.Query)('to')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, String, Object, Object, String, String]),
    __metadata("design:returntype", Promise)
], EventController.prototype, "byType", null);
__decorate([
    (0, common_1.Get)('user'),
    __param(0, (0, common_1.Res)({ passthrough: true })),
    __param(1, (0, common_1.Query)('userId')),
    __param(2, (0, common_1.Query)('limit')),
    __param(3, (0, common_1.Query)('offset')),
    __param(4, (0, common_1.Query)('from')),
    __param(5, (0, common_1.Query)('to')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, String, Object, Object, String, String]),
    __metadata("design:returntype", Promise)
], EventController.prototype, "byUser", null);
exports.EventController = EventController = __decorate([
    (0, common_1.Controller)('admin/events'),
    (0, common_1.UseGuards)(jwt_auth_guard_1.JwtAuthGuard, session_guard_1.SessionGuard, tenant_guard_1.TenantGuard),
    (0, common_1.UseInterceptors)(cache_control_interceptor_1.CacheControlInterceptor),
    __metadata("design:paramtypes", [event_service_1.EventLogService])
], EventController);
//# sourceMappingURL=event.controller.js.map