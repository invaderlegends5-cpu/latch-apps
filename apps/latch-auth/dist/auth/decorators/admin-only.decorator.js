"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AdminOnly = void 0;
const common_1 = require("@nestjs/common");
const roles_decorator_1 = require("./roles.decorator");
const AdminOnly = () => (0, common_1.SetMetadata)(roles_decorator_1.ROLES_KEY, ['ADMIN']);
exports.AdminOnly = AdminOnly;
//# sourceMappingURL=admin-only.decorator.js.map