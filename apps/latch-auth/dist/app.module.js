"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AppModule = void 0;
const common_1 = require("@nestjs/common");
const config_1 = require("@nestjs/config");
const throttler_1 = require("@nestjs/throttler");
const schedule_1 = require("@nestjs/schedule");
const prisma_service_1 = require("./prisma/prisma.service");
const auth_module_1 = require("./auth/auth.module");
const users_module_1 = require("./users/users.module");
const protected_module_1 = require("./protected/protected.module");
const events_module_1 = require("./events/events.module");
const security_module_1 = require("./security/security.module");
const health_module_1 = require("./health/health.module");
let AppModule = class AppModule {
};
exports.AppModule = AppModule;
exports.AppModule = AppModule = __decorate([
    (0, common_1.Module)({
        imports: [
            config_1.ConfigModule.forRoot({ isGlobal: true }),
            security_module_1.SecurityModule,
            throttler_1.ThrottlerModule.forRoot([
                {
                    name: 'otpRequest',
                    ttl: 300,
                    limit: 3,
                },
                {
                    name: 'otpVerify',
                    ttl: 600,
                    limit: 6,
                },
                {
                    name: 'refresh',
                    ttl: 60,
                    limit: 20,
                },
                {
                    name: 'default',
                    ttl: 60,
                    limit: 100,
                },
            ]),
            schedule_1.ScheduleModule.forRoot(),
            auth_module_1.AuthModule,
            users_module_1.UsersModule,
            protected_module_1.ProtectedModule,
            events_module_1.EventsModule,
            health_module_1.HealthModule,
        ],
        providers: [prisma_service_1.PrismaService,
        ],
    })
], AppModule);
//# sourceMappingURL=app.module.js.map