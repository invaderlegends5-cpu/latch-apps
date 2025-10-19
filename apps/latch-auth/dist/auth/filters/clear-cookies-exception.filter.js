"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ClearCookiesExceptionFilter = void 0;
const common_1 = require("@nestjs/common");
const clear_cookies_unauthorized_exception_1 = require("../exceptions/clear-cookies-unauthorized.exception");
const cookie_util_1 = require("../utils/cookie.util");
let ClearCookiesExceptionFilter = class ClearCookiesExceptionFilter {
    catch(exception, host) {
        const ctx = host.switchToHttp();
        const res = ctx.getResponse();
        (0, cookie_util_1.clearRefreshCookies)(res);
        res.status(exception.getStatus()).json({
            statusCode: exception.getStatus(),
            message: exception.message,
            clearCookies: true,
        });
    }
};
exports.ClearCookiesExceptionFilter = ClearCookiesExceptionFilter;
exports.ClearCookiesExceptionFilter = ClearCookiesExceptionFilter = __decorate([
    (0, common_1.Catch)(clear_cookies_unauthorized_exception_1.ClearCookiesUnauthorizedException)
], ClearCookiesExceptionFilter);
//# sourceMappingURL=clear-cookies-exception.filter.js.map