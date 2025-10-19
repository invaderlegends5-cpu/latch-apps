"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthModule = void 0;
const common_1 = require("@nestjs/common");
const passport_1 = require("@nestjs/passport");
const config_1 = require("@nestjs/config");
const core_1 = require("@nestjs/core");
const jwt_1 = require("@nestjs/jwt");
const events_module_1 = require("../events/events.module");
const auth_service_1 = require("./auth.service");
const jwt_strategy_1 = require("./jwt.strategy");
const normalize_request_interceptor_1 = require("./interceptors/normalize-request.interceptor");
const auth_controller_1 = require("./auth.controller");
const csrf_guard_1 = require("./guards/csrf.guard");
const prisma_service_1 = require("../prisma/prisma.service");
const event_service_1 = require("../events/event.service");
const session_guard_1 = require("./guards/session.guard");
let AuthModule = class AuthModule {
};
exports.AuthModule = AuthModule;
exports.AuthModule = AuthModule = __decorate([
    (0, common_1.Module)({
        imports: [
            passport_1.PassportModule.register({ defaultStrategy: 'jwt' }),
            jwt_1.JwtModule.register({
                secret: process.env.JWT_SECRET ?? 'dev_jwt_secret_change_me',
                signOptions: { expiresIn: '15m' },
            }),
            (0, common_1.forwardRef)(() => events_module_1.EventsModule),
            config_1.ConfigModule,
        ],
        controllers: [auth_controller_1.AuthController],
        providers: [
            auth_service_1.AuthService,
            prisma_service_1.PrismaService,
            jwt_strategy_1.JwtStrategy,
            csrf_guard_1.CsrfGuard,
            event_service_1.EventLogService,
            session_guard_1.SessionGuard,
            {
                provide: core_1.APP_INTERCEPTOR,
                useClass: normalize_request_interceptor_1.NormalizeRequestInterceptor,
            },
        ],
        exports: [auth_service_1.AuthService],
    })
], AuthModule);
//# sourceMappingURL=auth.module.js.map