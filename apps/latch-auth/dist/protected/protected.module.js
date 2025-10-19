"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ProtectedModule = void 0;
const common_1 = require("@nestjs/common");
const config_1 = require("@nestjs/config");
const protected_controller_1 = require("./protected.controller");
const prisma_service_1 = require("../prisma/prisma.service");
const event_service_1 = require("../events/event.service");
const session_guard_1 = require("../auth/guards/session.guard");
const auth_module_1 = require("../auth/auth.module");
let ProtectedModule = class ProtectedModule {
};
exports.ProtectedModule = ProtectedModule;
exports.ProtectedModule = ProtectedModule = __decorate([
    (0, common_1.Module)({
        imports: [auth_module_1.AuthModule, config_1.ConfigModule],
        controllers: [protected_controller_1.ProtectedController],
        providers: [
            prisma_service_1.PrismaService,
            event_service_1.EventLogService,
            session_guard_1.SessionGuard,
        ],
        exports: [session_guard_1.SessionGuard],
    })
], ProtectedModule);
//# sourceMappingURL=protected.module.js.map