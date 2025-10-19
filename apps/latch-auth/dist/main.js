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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const helmet_1 = __importDefault(require("helmet"));
const core_1 = require("@nestjs/core");
const Sentry = __importStar(require("@sentry/node"));
const app_module_1 = require("./app.module");
const cookie_parser_1 = __importDefault(require("cookie-parser"));
const common_1 = require("@nestjs/common");
const cache_control_interceptor_1 = require("./interceptors/cache-control.interceptor");
const clear_cookies_exception_filter_1 = require("./auth/filters/clear-cookies-exception.filter");
require("tsconfig-paths/register");
Sentry.init({
    dsn: process.env.SENTRY_DSN,
    tracesSampleRate: 0.1,
});
async function bootstrap() {
    const app = await core_1.NestFactory.create(app_module_1.AppModule);
    app.use((0, cookie_parser_1.default)(process.env.COOKIE_SECRET ?? 'dev_cookie_secret'));
    const frontendOrigin = process.env.FRONTEND_ORIGIN || 'http://localhost:5173';
    app.use((0, helmet_1.default)({
        contentSecurityPolicy: process.env.NODE_ENV === 'production'
            ? {
                directives: {
                    defaultSrc: ["'self'"],
                    scriptSrc: ["'self'", "'unsafe-inline'"],
                    styleSrc: ["'self'", "'unsafe-inline'"],
                    imgSrc: ["'self'", 'data:'],
                    connectSrc: ["'self'", frontendOrigin],
                },
            }
            : false,
    }));
    if (process.env.NODE_ENV === 'production') {
        app.use(helmet_1.default.hsts({
            maxAge: 31536000,
            includeSubDomains: true,
            preload: true,
        }));
    }
    app.useGlobalInterceptors(new cache_control_interceptor_1.CacheControlInterceptor());
    app.useGlobalPipes(new common_1.ValidationPipe({ whitelist: true }));
    app.enableCors({
        origin: process.env.FRONTEND_ORIGIN ?? 'http://localhost:5173',
        credentials: true,
    });
    app.setGlobalPrefix('v1');
    app.enableShutdownHooks();
    app.useGlobalFilters(new clear_cookies_exception_filter_1.ClearCookiesExceptionFilter());
    await app.listen(process.env.PORT ? Number(process.env.PORT) : 3000);
    console.log(`Latch API running on ${await app.getUrl()}`);
}
void bootstrap();
//# sourceMappingURL=main.js.map