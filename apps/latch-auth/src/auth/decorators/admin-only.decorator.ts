// src/auth/decorators/admin-only.decorator.ts
import { SetMetadata } from '@nestjs/common';
import { ROLES_KEY } from './roles.decorator';

/**
 * AdminOnly()
 *
 * Static decorator that enforces ADMIN role requirement.
 * Works seamlessly with RolesGuard for:
 * - Tenant-scoped role validation
 * - Full audit logging (granted/denied)
 * - Security event integrity chaining
 *
 * Usage:
 *   @UseGuards(JwtAuthGuard, TenantGuard, RolesGuard)
 *   @AdminOnly()
 *   adminMethod() { ... }
 */
export const AdminOnly = () => SetMetadata(ROLES_KEY, ['ADMIN']);
