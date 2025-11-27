// src/admin/admin.controller.ts
import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Param,
  Body,
  UseGuards,
  Query,
  BadRequestException,
  Logger,
  HttpStatus,
  Req,
  HttpCode,
  DefaultValuePipe,
  ParseIntPipe,
  ValidationPipe,
  UseInterceptors,
  ClassSerializerInterceptor,
  ForbiddenException,
  NotFoundException,
} from '@nestjs/common';
import type { Request } from 'express';
import { 
  ApiTags, 
  ApiOperation, 
  ApiResponse, 
  ApiParam, 
  ApiQuery,
  ApiBearerAuth,
  ApiSecurity,
  ApiBody,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { CsrfGuard } from '../auth/guards/csrf.guard';
import { AdminOnly } from '../auth/decorators/admin-only.decorator';
import { Roles } from '../auth/decorators/roles.decorator';
import { EventLogService } from '../events/event.service';
import { AdminService } from './admin.service';
import { UpdateUserRoleDto, UserRoleOperation } from './dto/update-user-role.dto';
import { TenantGuard } from '@/auth/guards/tenant.guard';
import { IPReputationService } from '../ip-reputation/ip-reputation.service';
// Response DTOs for better API documentation
class UserResponseDto {
  id: string;
  name: string;
  email: string;
  phone: string;
  tenantId: string;
  createdAt: Date;
  updatedAt: Date;
  isPhoneVerified: boolean;
  isEmailVerified: boolean;
  roleCount: number;
  activeRoles: number;
  tenant: {
    id: string;
    name: string;
    slug: string;
  };
  roles: Array<{
    roleId: string;
    role: {
      id: string;
      name: string;
      description: string;
      isSystem: boolean;
      isActive: boolean;
      validFrom: Date;
      validUntil: Date;
    };
  }>;
}

class PaginatedUsersResponseDto {
  data: UserResponseDto[];
  meta: {
    total: number;
    limit: number;
    offset: number;
    hasNext: boolean;
  };
}

class AuditEventResponseDto {
  id: string;
  type: string;
  severity: string;
  userId: string;
  tenantId: string;
  metadata: any;
  ipAddress: string;
  userAgent: string;
  integrityHash: string;
  createdAt: Date;
  user?: {
    id: string;
    name: string;
    phone: string;
  };
  tenant?: {
    id: string;
    name: string;
    slug: string;
  };
}

class PaginatedAuditEventsResponseDto {
  data: AuditEventResponseDto[];
  meta: {
    total: number;
    limit: number;
    offset: number;
    hasNext: boolean;
  };
}

class RoleAnalyticsResponseDto {
  roleDistribution: Array<{
    name: string;
    _count: number;
    _avg: {
      priority: number;
    };
  }>;
  userRoleStats: {
    _count: {
      id: number;
      userId: number;
      roleId: number;
    };
  };
  permissionStats: {
    _count: {
      id: number;
    };
  };
  timestamp: Date;
}

class TenantUserStatsResponseDto {
  totalUsers: number;
  activeUsers: number;
  roleDistribution: Array<{
    name: string;
    _count: number;
  }>;
  securityEventsLast30Days: number;
  timestamp: Date;
}

class BulkOperationResponseDto {
  totalUsers: number;
  successfulUpdates: number;
  failedUpdates: number;
  results: {
    userId: string;
    success: boolean;
    error?: string;
  }[];
}

class UserRoleDetailsResponseDto {
  userId: string;
  name: string;
  email: string;
  roles: Array<{
    roleId: string;
    roleName: string;
    roleDescription: string;
    permissions: Array<{
      permissionId: string;
      permissionName: string;
      resource: string;
      action: string;
      allowed: boolean;
    }>;
  }>;
}

@ApiTags('admin')
@Controller('v1/admin')
@ApiBearerAuth()
@ApiSecurity('csrf-token')
@UseInterceptors(ClassSerializerInterceptor)
@UseGuards(JwtAuthGuard, RolesGuard, CsrfGuard)
export class AdminController {
  private readonly logger = new Logger(AdminController.name);

  constructor(
    private readonly adminService: AdminService,
    private readonly eventLog: EventLogService,
    private readonly ipReputationService: IPReputationService,
  ) {}

  @Get('users')
  @UseGuards(JwtAuthGuard, RolesGuard, TenantGuard, CsrfGuard)
  @Roles('ADMIN', 'SUPER_ADMIN')
  @ApiOperation({ 
    summary: 'List all users with pagination and filtering', 
    description: 'Requires ADMIN or SUPER_ADMIN role. Returns paginated list of users with optional filtering by tenant, search term, and role details.'
  })
  @ApiQuery({ name: 'limit', required: false, type: Number, description: 'Number of users to return (1-100)', example: 50 })
  @ApiQuery({ name: 'offset', required: false, type: Number, description: 'Offset for pagination', example: 0 })
  @ApiQuery({ name: 'tenantId', required: false, type: String, description: 'Filter by tenant ID', example: 'tenant-uuid' })
  @ApiQuery({ name: 'includeRoleDetails', required: false, type: Boolean, description: 'Include detailed role information', example: false })
  @ApiQuery({ name: 'search', required: false, type: String, description: 'Search term for name, email, or phone', example: 'john' })
  @ApiQuery({ name: 'status', required: false, type: String, description: 'Filter by user status', example: 'active' })
  @ApiResponse({ 
    status: 200, 
    description: 'Successfully retrieved paginated users', 
    type: PaginatedUsersResponseDto 
  })
  @ApiResponse({ status: 400, description: 'Invalid parameters' })
  @ApiResponse({ status: 403, description: 'Insufficient permissions' })
  async findAllUsers(
    @Req() req: Request,
    @Query('limit', new DefaultValuePipe(50), ParseIntPipe) limit: number,
    @Query('offset', new DefaultValuePipe(0), ParseIntPipe) offset: number,
    @Query('tenantId') tenantId?: string,
    @Query('includeRoleDetails') includeRoleDetails?: string,
    @Query('search') search?: string,
    @Query('status') status?: string,
  ) {
    const ipAddress = req.ip || req.socket.remoteAddress || 'unknown';
    if (await this.ipReputationService.isIPBlocked(ipAddress)) {
      await this.eventLog.logEvent('SECURITY_CSRF_ERROR', {
        userId: req.user?.sub || null,
        tenantId: req.user?.tenantId || null,
        metadata: { 
          reason: 'BLOCKED_IP_ADMIN_ACCESS_ATTEMPT',
          endpoint: '/admin/users',
          action: 'LIST_USERS',
        },
        ipAddress,
        userAgent: req.headers['user-agent'] as string,
        severity: 'CRITICAL',
      });
      
      throw new ForbiddenException('Admin access denied - IP address is blocked');
    }

    const includeRoleDetailsBool = includeRoleDetails === 'true';

    const sanitizedTenantId = (tenantId && tenantId.trim() !== '') ? tenantId : undefined;
    const sanitizedSearch = (search && search.trim() !== '') ? search : undefined;
    const sanitizedStatus = (status && status.trim() !== '') ? status : undefined;

    // Validate parameters
    if (limit < 1 || limit > 100) {
      await this.eventLog.logEvent('ADMIN_VALIDATION_ERROR', {
        userId: req.user?.sub || null,
        tenantId: req.user?.tenantId || null,
        metadata: {
          reason: 'invalid_pagination_params',
          limit,
          offset,
        },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] as string,
        severity: 'SECURITY',
      });
      throw new BadRequestException('Limit must be between 1 and 100');
    }
    if (offset < 0) {
      await this.eventLog.logEvent('ADMIN_VALIDATION_ERROR', {
        userId: req.user?.sub || null,
        tenantId: req.user?.tenantId || null,
        metadata: {
          reason: 'invalid_offset_param',
          offset,
        },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] as string,
        severity: 'SECURITY',
      });
      throw new BadRequestException('Offset must be >= 0');
    }

    // Call the service with the sanitized parameters
    const result = await this.adminService.findAllUsers(
      limit,
      offset,
      sanitizedTenantId, // Use sanitized value
      includeRoleDetailsBool,
      sanitizedSearch, // Use sanitized value
      sanitizedStatus, // Use sanitized value
    );

    await this.eventLog.logEvent('USER_LIST_ACCESSED', {
      userId: req.user?.sub || null,
      tenantId: req.user?.tenantId || null,
      metadata: {
        action: 'LIST_USERS',
        limit,
        offset,
        tenantId: sanitizedTenantId, // Log the sanitized value
        includeRoleDetails: includeRoleDetailsBool,
        search: sanitizedSearch, // Log the sanitized value
        status: sanitizedStatus, // Log the sanitized value
        total: result.meta.total,
      },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'] as string,
      severity: 'INFO',
    });

    return result;
  }

  @Patch('users/roles')
  @Roles('ADMIN', 'SUPER_ADMIN')
  @UseGuards(TenantGuard)
  @ApiOperation({ 
    summary: 'Update user roles with advanced operations', 
    description: 'Requires ADMIN or SUPER_ADMIN role. Performs advanced role operations including ASSIGN, REMOVE, REPLACE, TEMPORARY_ASSIGN, and INHERIT.'
  })
  @ApiBody({ type: UpdateUserRoleDto })
  @ApiResponse({ 
    status: 200, 
    description: 'Successfully updated user roles', 
  })
  @ApiResponse({ status: 400, description: 'Invalid input or missing parameters' })
  @ApiResponse({ status: 403, description: 'Insufficient permissions' })
  @ApiResponse({ status: 404, description: 'User or role not found' })
  async updateUserRole(
    @Body() updateUserRoleDto: UpdateUserRoleDto,
    @Req() req: Request,
  ) {

    const ipAddress = req.ip || req.socket.remoteAddress || 'unknown';
    if (await this.ipReputationService.isIPBlocked(ipAddress)) {
      await this.eventLog.logEvent('SECURITY_CSRF_ERROR', {
        userId: req.user?.sub || null,
        tenantId: req.user?.tenantId || null,
        metadata: { 
          reason: 'BLOCKED_IP_ADMIN_ACCESS_ATTEMPT',
          endpoint: '/admin/users/roles',
          action: 'UPDATE_USER_ROLE',
          targetUserId: updateUserRoleDto.userId,
        },
        ipAddress,
        userAgent: req.headers['user-agent'] as string,
        severity: 'CRITICAL',
      });
      
      throw new ForbiddenException('Admin access denied - IP address is blocked');
    }

    // Pre-validation logging
    await this.eventLog.logEvent('USER_PROFILE_UPDATE', {
      userId: req.user?.sub || null,
      tenantId: req.user?.tenantId || null,
      metadata: {
        action: 'UPDATE_USER_ROLE_ATTEMPT',
        targetUserId: updateUserRoleDto.userId,
        tenantId: updateUserRoleDto.tenantId,
        operation: updateUserRoleDto.operation,
        roleCount: updateUserRoleDto.roles.length,
      },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'] as string,
      severity: 'SECURITY',
    });

    const result = await this.adminService.updateUserRole(
      updateUserRoleDto,
      req.user?.sub || '',
    );

    await this.eventLog.logEvent('USER_PROFILE_UPDATE', {
      userId: req.user?.sub || null,
      tenantId: req.user?.tenantId || null,
      metadata: {
        action: 'UPDATE_USER_ROLE_SUCCESS',
        targetUserId: updateUserRoleDto.userId,
        tenantId: updateUserRoleDto.tenantId,
        operation: updateUserRoleDto.operation,
        roleCount: updateUserRoleDto.roles.length,
      },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'] as string,
      severity: 'SECURITY',
    });

    return result;
  }

  @Get('audit/events')
  @Roles('ADMIN', 'SUPER_ADMIN')
  @UseGuards(TenantGuard)
  @ApiOperation({ 
    summary: 'Get audit events with advanced filtering', 
    description: 'Requires ADMIN or SUPER_ADMIN role. Returns paginated audit events with comprehensive filtering options.'
  })
  @ApiQuery({ name: 'limit', required: false, type: Number, description: 'Number of events to return (1-100)', example: 50 })
  @ApiQuery({ name: 'offset', required: false, type: Number, description: 'Offset for pagination', example: 0 })
  @ApiQuery({ name: 'type', required: false, type: String, description: 'Filter by event type', example: 'USER_PROFILE_UPDATE' })
  @ApiQuery({ name: 'userId', required: false, type: String, description: 'Filter by user ID', example: 'user-uuid' })
  @ApiQuery({ name: 'startDate', required: false, type: String, description: 'Filter events from this date (ISO format)', example: '2023-01-01T00:00:00Z' })
  @ApiQuery({ name: 'endDate', required: false, type: String, description: 'Filter events until this date (ISO format)', example: '2023-12-31T23:59:59Z' })
  @ApiQuery({ name: 'severity', required: false, type: String, description: 'Filter by severity level', example: 'SECURITY' })
  @ApiQuery({ name: 'tenantId', required: false, type: String, description: 'Filter by tenant ID', example: 'tenant-uuid' })
  @ApiResponse({ 
    status: 200, 
    description: 'Successfully retrieved audit events', 
    type: PaginatedAuditEventsResponseDto 
  })
  @ApiResponse({ status: 400, description: 'Invalid parameters' })
  @ApiResponse({ status: 403, description: 'Insufficient permissions' })
  async getAuditEvents(
    @Req() req: Request,
    @Query('limit', new DefaultValuePipe('50'), ParseIntPipe) limit: number,
    @Query('offset', new DefaultValuePipe('0'), ParseIntPipe) offset: number,
    @Query('type') type?: string,
    @Query('userId') userId?: string,
    @Query('startDate') startDate?: string,
    @Query('endDate') endDate?: string,
    @Query('severity') severity?: string,
    @Query('tenantId') tenantId?: string,
  ) {
    const ipAddress = req.ip || req.socket.remoteAddress || 'unknown';
    if (await this.ipReputationService.isIPBlocked(ipAddress)) {
      await this.eventLog.logEvent('SECURITY_CSRF_ERROR', {
        userId: req.user?.sub || null,
        tenantId: req.user?.tenantId || null,
        metadata: { 
          reason: 'BLOCKED_IP_ADMIN_ACCESS_ATTEMPT',
          endpoint: '/admin/audit/events',
          action: 'GET_AUDIT_EVENTS',
        },
        ipAddress,
        userAgent: req.headers['user-agent'] as string,
        severity: 'CRITICAL',
      });
      
      throw new ForbiddenException('Admin access denied - IP address is blocked');
    }

    // Validate parameters
    if (limit < 1 || limit > 100) {
      await this.eventLog.logEvent('ADMIN_VALIDATION_ERROR', {
        userId: req.user?.sub || null,
        tenantId: req.user?.tenantId || null,
        metadata: {
          reason: 'invalid_pagination_params',
          limit,
          offset,
        },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] as string,
        severity: 'SECURITY',
      });
      throw new BadRequestException('Limit must be between 1 and 100');
    }
    if (offset < 0) {
      await this.eventLog.logEvent('ADMIN_VALIDATION_ERROR', {
        userId: req.user?.sub || null,
        tenantId: req.user?.tenantId || null,
        metadata: {
          reason: 'invalid_offset_param',
          offset,
        },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] as string,
        severity: 'SECURITY',
      });
      throw new BadRequestException('Offset must be >= 0');
    }

    // Validate date parameters if provided
    let start: Date | undefined;
    let end: Date | undefined;
    
    if (startDate) {
      const parsedStart = new Date(startDate);
      if (isNaN(parsedStart.getTime())) {
        await this.eventLog.logEvent('ADMIN_VALIDATION_ERROR', {
          userId: req.user?.sub || null,
          tenantId: req.user?.tenantId || null,
          metadata: {
            reason: 'invalid_start_date_format',
            startDate,
          },
          ipAddress: req.ip,
          userAgent: req.headers['user-agent'] as string,
          severity: 'SECURITY',
        });
        throw new BadRequestException('Invalid startDate format. Must be ISO 8601.');
      }
      start = parsedStart;
    }
    
    if (endDate) {
      const parsedEnd = new Date(endDate);
      if (isNaN(parsedEnd.getTime())) {
        await this.eventLog.logEvent('ADMIN_VALIDATION_ERROR', {
          userId: req.user?.sub || null,
          tenantId: req.user?.tenantId || null,
          metadata: {
            reason: 'invalid_end_date_format',
            endDate,
          },
          ipAddress: req.ip,
          userAgent: req.headers['user-agent'] as string,
          severity: 'SECURITY',
        });
        throw new BadRequestException('Invalid endDate format. Must be ISO 8601.');
      }
      end = parsedEnd;
    }

    const result = await this.adminService.getAuditEvents(
      limit,
      offset,
      type,
      userId,
      start,
      end,
      severity,
      tenantId,
    );

    await this.eventLog.logEvent('AUDIT_TRAIL_ACCESSED', {
      userId: req.user?.sub || null,
      tenantId: req.user?.tenantId || null,
      metadata: {
        action: 'GET_AUDIT_EVENTS',
        limit,
        offset,
        type,
        userId,
        startDate,
        endDate,
        severity,
        tenantId,
        total: result.meta?.total || 0,
      },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'] as string,
      severity: 'INFO',
    });

    return result;
  }

  @Get('analytics/roles/:tenantId')
  @Roles('ADMIN', 'SUPER_ADMIN')
  @UseGuards(TenantGuard)
  @ApiOperation({ 
    summary: 'Get role analytics for a tenant', 
    description: 'Requires ADMIN or SUPER_ADMIN role. Returns comprehensive role distribution and usage statistics for a tenant.'
  })
  @ApiParam({ name: 'tenantId', description: 'Tenant ID', example: 'tenant-uuid' })
  @ApiResponse({ 
    status: 200, 
    description: 'Successfully retrieved role analytics', 
    type: RoleAnalyticsResponseDto 
  })
  @ApiResponse({ status: 403, description: 'Insufficient permissions' })
  @ApiResponse({ status: 404, description: 'Tenant not found' })
  async getRoleAnalytics(
    @Param('tenantId') tenantId: string,
    @Req() req: Request,
  ) {
    const ipAddress = req.ip || req.socket.remoteAddress || 'unknown';
    if (await this.ipReputationService.isIPBlocked(ipAddress)) {
      await this.eventLog.logEvent('SECURITY_CSRF_ERROR', {
        userId: req.user?.sub || null,
        tenantId: req.user?.tenantId || null,
        metadata: { 
          reason: 'BLOCKED_IP_ADMIN_ACCESS_ATTEMPT',
          endpoint: `/admin/analytics/roles/${tenantId}`,
          action: 'GET_ROLE_ANALYTICS',
          targetTenantId: tenantId,
        },
        ipAddress,
        userAgent: req.headers['user-agent'] as string,
        severity: 'CRITICAL',
      });
      
      throw new ForbiddenException('Admin access denied - IP address is blocked');
    }

    const result = await this.adminService.getRoleAnalytics(tenantId);

    await this.eventLog.logEvent('AUDIT_TRAIL_ACCESSED', {
      userId: req.user?.sub || null,
      tenantId: req.user?.tenantId || null,
      metadata: {
        action: 'GET_ROLE_ANALYTICS',
        targetTenantId: tenantId,
      },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'] as string,
      severity: 'INFO',
    });

    return result;
  }

  @Get('analytics/users/:tenantId')
  @Roles('ADMIN', 'SUPER_ADMIN')
  @UseGuards(TenantGuard)
  @ApiOperation({ 
    summary: 'Get user statistics for a tenant', 
    description: 'Requires ADMIN or SUPER_ADMIN role. Returns comprehensive user statistics and role distribution for a tenant.'
  })
  @ApiParam({ name: 'tenantId', description: 'Tenant ID', example: 'tenant-uuid' })
  @ApiResponse({ 
    status: 200, 
    description: 'Successfully retrieved user statistics', 
    type: TenantUserStatsResponseDto 
  })
  @ApiResponse({ status: 403, description: 'Insufficient permissions' })
  @ApiResponse({ status: 404, description: 'Tenant not found' })
  async getTenantUserStats(
    @Param('tenantId') tenantId: string,
    @Req() req: Request,
  ) {
    const ipAddress = req.ip || req.socket.remoteAddress || 'unknown';
    if (await this.ipReputationService.isIPBlocked(ipAddress)) {
      await this.eventLog.logEvent('SECURITY_CSRF_ERROR', {
        userId: req.user?.sub || null,
        tenantId: req.user?.tenantId || null,
        metadata: { 
          reason: 'BLOCKED_IP_ADMIN_ACCESS_ATTEMPT',
          endpoint: `/admin/analytics/users/${tenantId}`,
          action: 'GET_TENANT_USER_STATS',
          targetTenantId: tenantId,
        },
        ipAddress,
        userAgent: req.headers['user-agent'] as string,
        severity: 'CRITICAL',
      });
      
      throw new ForbiddenException('Admin access denied - IP address is blocked');
    }

    const result = await this.adminService.getTenantUserStats(tenantId);

    await this.eventLog.logEvent('AUDIT_TRAIL_ACCESSED', {
      userId: req.user?.sub || null,
      tenantId: req.user?.tenantId || null,
      metadata: {
        action: 'GET_TENANT_USER_STATS',
        targetTenantId: tenantId,
      },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'] as string,
      severity: 'INFO',
    });

    return result;
  }

  @Post('users/bulk/roles')
  @Roles('ADMIN', 'SUPER_ADMIN')
  @ApiOperation({ 
    summary: 'Bulk update user roles', 
    description: 'Requires ADMIN or SUPER_ADMIN role. Performs bulk role operations on multiple users simultaneously.'
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        userIds: {
          type: 'array',
          items: { type: 'string' },
          example: ['user-uuid-1', 'user-uuid-2']
        },
        roleIds: {
          type: 'array',
          items: { type: 'string' },
          example: ['role-uuid-1', 'role-uuid-2']
        },
        operation: {
          type: 'string',
          enum: ['ASSIGN', 'REMOVE', 'REPLACE'],
          example: 'ASSIGN'
        },
        reason: {
          type: 'string',
          example: 'Bulk role assignment'
        }
      }
    }
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Successfully performed bulk role updates', 
    type: BulkOperationResponseDto 
  })
  @ApiResponse({ status: 400, description: 'Invalid input or parameters' })
  @ApiResponse({ status: 403, description: 'Insufficient permissions' })
  async bulkUpdateUserRoles(
    @Req() req: Request,
    @Body('userIds') userIds: string[],
    @Body('roleIds') roleIds: string[],
    @Body('operation') operation: 'ASSIGN' | 'REMOVE' | 'REPLACE',
    @Body('reason') reason?: string,
  ) {
    const ipAddress = req.ip || req.socket.remoteAddress || 'unknown';
    if (await this.ipReputationService.isIPBlocked(ipAddress)) {
      await this.eventLog.logEvent('SECURITY_CSRF_ERROR', {
        userId: req.user?.sub || null,
        tenantId: req.user?.tenantId || null,
        metadata: { 
          reason: 'BLOCKED_IP_ADMIN_ACCESS_ATTEMPT',
          endpoint: '/admin/users/bulk/roles',
          action: 'BULK_ROLE_UPDATE',
          totalUsers: userIds.length,
          totalRoles: roleIds.length,
        },
        ipAddress,
        userAgent: req.headers['user-agent'] as string,
        severity: 'CRITICAL',
      });
      
      throw new ForbiddenException('Admin access denied - IP address is blocked');
    }

    // Validate input
    if (!Array.isArray(userIds) || userIds.length === 0) {
      await this.eventLog.logEvent('ADMIN_VALIDATION_ERROR', {
        userId: req.user?.sub || null,
        tenantId: req.user?.tenantId || null,
        metadata: {
          reason: 'invalid_user_ids_array',
          userIds,
        },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] as string,
        severity: 'SECURITY',
      });
      throw new BadRequestException('userIds must be a non-empty array');
    }

    if (!Array.isArray(roleIds) || roleIds.length === 0) {
      await this.eventLog.logEvent('ADMIN_VALIDATION_ERROR', {
        userId: req.user?.sub || null,
        tenantId: req.user?.tenantId || null,
        metadata: {
          reason: 'invalid_role_ids_array',
          roleIds,
        },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] as string,
        severity: 'SECURITY',
      });
      throw new BadRequestException('roleIds must be a non-empty array');
    }

    if (!['ASSIGN', 'REMOVE', 'REPLACE'].includes(operation)) {
      await this.eventLog.logEvent('ADMIN_VALIDATION_ERROR', {
        userId: req.user?.sub || null,
        tenantId: req.user?.tenantId || null,
        metadata: {
          reason: 'invalid_operation_type',
          operation,
        },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] as string,
        severity: 'SECURITY',
      });
      throw new BadRequestException('Operation must be ASSIGN, REMOVE, or REPLACE');
    }

    const result = await this.adminService.bulkUpdateUserRoles(
      userIds,
      roleIds,
      operation,
      req.user?.sub || '',
      reason,
    );

    await this.eventLog.logEvent('USER_PROFILE_UPDATE', {
      userId: req.user?.sub || null,
      tenantId: req.user?.tenantId || null,
      metadata: {
        action: 'BULK_ROLE_UPDATE_COMPLETED',
        totalUsers: userIds.length,
        successfulUpdates: result.successfulUpdates,
        failedUpdates: result.failedUpdates,
        operation,
        roleIds,
        reason,
      },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'] as string,
      severity: 'SECURITY',
    });

    return result;
  }

  @Get('users/:userId/roles')
  @Roles('ADMIN', 'SUPER_ADMIN')
  @ApiOperation({ 
    summary: 'Get detailed role information for a user', 
    description: 'Requires ADMIN or SUPER_ADMIN role. Returns comprehensive role and permission details for a specific user.'
  })
  @ApiParam({ name: 'userId', description: 'User ID', example: 'user-uuid' })
  @ApiResponse({ 
    status: 200, 
    description: 'Successfully retrieved user role details', 
    type: UserRoleDetailsResponseDto 
  })
  @ApiResponse({ status: 403, description: 'Insufficient permissions' })
  @ApiResponse({ status: 404, description: 'User not found' })
  async getUserRoleDetails(
    @Param('userId') userId: string,
    @Req() req: Request,
  ) {
    const ipAddress = req.ip || req.socket.remoteAddress || 'unknown';
    if (await this.ipReputationService.isIPBlocked(ipAddress)) {
      await this.eventLog.logEvent('SECURITY_CSRF_ERROR', {
        userId: req.user?.sub || null,
        tenantId: req.user?.tenantId || null,
        metadata: { 
          reason: 'BLOCKED_IP_ADMIN_ACCESS_ATTEMPT',
          endpoint: `/admin/users/${userId}/roles`,
          action: 'GET_USER_ROLE_DETAILS',
          targetUserId: userId,
        },
        ipAddress,
        userAgent: req.headers['user-agent'] as string,
        severity: 'CRITICAL',
      });
      
      throw new ForbiddenException('Admin access denied - IP address is blocked');
    }

    const result = await this.adminService.getUserRoleDetails(userId);

    await this.eventLog.logEvent('USER_DATA_ACCESSED', {
      userId: req.user?.sub || null,
      tenantId: req.user?.tenantId || null,
      metadata: {
        action: 'GET_USER_ROLE_DETAILS',
        targetUserId: userId,
      },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'] as string,
      severity: 'INFO',
    });

    return result;
  }
}