"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.NormalizeRequestInterceptor = void 0;
const common_1 = require("@nestjs/common");
const normalize_util_1 = require("../utils/normalize.util");
let NormalizeRequestInterceptor = class NormalizeRequestInterceptor {
    intercept(context, next) {
        const req = context.switchToHttp().getRequest();
        req.normalizedIp = (0, normalize_util_1.normalizeIp)(req.ip);
        req.normalizedUserAgent = (0, normalize_util_1.normalizeUserAgent)(req.headers['user-agent']);
        return next.handle();
    }
};
exports.NormalizeRequestInterceptor = NormalizeRequestInterceptor;
exports.NormalizeRequestInterceptor = NormalizeRequestInterceptor = __decorate([
    (0, common_1.Injectable)()
], NormalizeRequestInterceptor);
//# sourceMappingURL=normalize-request.interceptor.js.map