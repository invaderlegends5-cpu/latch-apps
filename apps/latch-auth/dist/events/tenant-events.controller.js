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
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.TenantEventsController = void 0;
const common_1 = require("@nestjs/common");
const event_service_1 = require("./event.service");
const jwt_auth_guard_1 = require("../auth/guards/jwt-auth.guard");
const tenant_guard_1 = require("../auth/guards/tenant.guard");
const authTypes = __importStar(require("../auth/types/auth.types"));
const session_guard_1 = require("../auth/guards/session.guard");
let TenantEventsController = class TenantEventsController {
    eventLog;
    constructor(eventLog) {
        this.eventLog = eventLog;
    }
    async recent(req, limit = 50, offset = 0) {
        const parsedLimit = Number(limit);
        const parsedOffset = Number(offset);
        if (isNaN(parsedLimit) || parsedLimit < 1 || parsedLimit > 1000) {
            throw new common_1.BadRequestException('Limit must be between 1 and 1000');
        }
        if (isNaN(parsedOffset) || parsedOffset < 0) {
            throw new common_1.BadRequestException('Offset must be >= 0');
        }
        const tenantId = req.user.tenantId;
        return this.eventLog.findRecent(parsedLimit, parsedOffset, tenantId, undefined);
    }
};
exports.TenantEventsController = TenantEventsController;
__decorate([
    (0, common_1.Get)('recent'),
    __param(0, (0, common_1.Req)()),
    __param(1, (0, common_1.Query)('limit')),
    __param(2, (0, common_1.Query)('offset')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object, Object]),
    __metadata("design:returntype", Promise)
], TenantEventsController.prototype, "recent", null);
exports.TenantEventsController = TenantEventsController = __decorate([
    (0, common_1.Controller)('tenant/events'),
    (0, common_1.UseGuards)(jwt_auth_guard_1.JwtAuthGuard, session_guard_1.SessionGuard, tenant_guard_1.TenantGuard),
    __metadata("design:paramtypes", [event_service_1.EventLogService])
], TenantEventsController);
//# sourceMappingURL=tenant-events.controller.js.map