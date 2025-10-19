"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ClearCookiesUnauthorizedException = void 0;
const common_1 = require("@nestjs/common");
class ClearCookiesUnauthorizedException extends common_1.UnauthorizedException {
    clearCookies = true;
    constructor(message) {
        super(message);
    }
}
exports.ClearCookiesUnauthorizedException = ClearCookiesUnauthorizedException;
//# sourceMappingURL=clear-cookies.exception.js.map