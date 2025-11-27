// src/admin/admin.service.ts
import { Injectable, Logger, NotFoundException, BadRequestException, ForbiddenException, UnauthorizedException, Inject } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { UpdateUserRoleDto, UserRoleOperation } from './dto/update-user-role.dto';
import { EventLogService } from '../events/event.service';
import { Prisma } from '@prisma/client';
import { generateIntegrityHash } from '@/auth/utils/hash.util';
import { v4 as uuidv4 } from 'uuid';
import { Redis } from 'ioredis';

@Injectable()
export class AdminService {
  private readonly logger = new Logger(AdminService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly eventLog: EventLogService,
    @Inject('REDIS') private readonly redis: Redis,
  ) {}

  async findAllUsers(
    limit = 50, 
    offset = 0, 
    tenantId?: string,
    includeRoleDetails = false,
    search?: string,
    status?: string,
  ) {
    // Validate inputs
    if (limit < 1 || limit > 100) {
      throw new BadRequestException('Limit must be between 1 and 100');
    }
    if (offset < 0) {
      throw new BadRequestException('Offset cannot be negative');
    }

    // Check cache first
    const cacheKey = `admin:users:limit:${limit}:offset:${offset}:tenant:${tenantId || 'all'}:search:${search || 'none'}:includeRoles:${includeRoleDetails}`;
    const cached = await this.redis.get(cacheKey);
    
    if (cached) {
      return JSON.parse(cached);
    }

    const where: any = {};
    
    if (tenantId) {
      // Validate tenant exists
      const tenantExists = await this.prisma.tenant.findUnique({
        where: { id: tenantId },
        select: { id: true },
      });
      
      if (!tenantExists) {
        throw new NotFoundException(`Tenant with id "${tenantId}" not found`);
      }
      
      where.tenantId = tenantId;
    }
    
    if (search) {
      where.OR = [
        { name: { contains: search, mode: 'insensitive' } },
        { email: { contains: search, mode: 'insensitive' } },
        { phone: { contains: search, mode: 'insensitive' } },
      ];
    }
    
    if (status) {
      // Add status filtering if needed (e.g., active/inactive)
      // where.status = status;
    }

    const [users, total] = await Promise.all([
      this.prisma.user.findMany({
        where,
        skip: offset,
        take: limit,
        orderBy: { createdAt: 'desc' },
        include: {
          tenant: {
            select: {
              id: true,
              name: true,
              slug: true,
            },
          },
          roles: {
            include: {
              role: {
                select: {
                  id: true,
                  name: true,
                  description: true,
                  isSystem: true,
                  createdAt: true,
                  validFrom: true,
                  validUntil: true,
                  isActive: true,
                },
              },
            },
            where: includeRoleDetails ? undefined : { role: { isActive: true } },
          },
        },
      }),
      this.prisma.user.count({ where }),
    ]);

    const result = {
      data: users.map(user => ({
        ...user,
        roleCount: user.roles.length,
        activeRoles: user.roles.filter(ur => ur.role.isActive).length,
      })),
      meta: {
        total,
        limit,
        offset,
        hasNext: offset + limit < total,
      },
    };

    // Cache for 5 minutes
    await this.redis.setex(cacheKey, 300, JSON.stringify(result));

    return result;
  }

  async updateUserRole(
    updateRoleDto: UpdateUserRoleDto,
    updatedByUserId: string,
  ) {
    
    console.log("DEBUG: AdminService.updateUserRole - Received DTO:", updateRoleDto);
  console.log("DEBUG: AdminService.updateUserRole - userId type:", typeof updateRoleDto.userId, "value:", updateRoleDto.userId);
  console.log("DEBUG: AdminService.updateUserRole - tenantId type:", typeof updateRoleDto.tenantId, "value:", updateRoleDto.tenantId);
  if (updateRoleDto.roles && updateRoleDto.roles[0]) {
    console.log("DEBUG: AdminService.updateUserRole - roles[0].roleId type:", typeof updateRoleDto.roles[0].roleId, "value:", updateRoleDto.roles[0].roleId);
  }

    const { userId, tenantId, operation, roles, reason, notifyUser, grantedBy, bypassHierarchyCheck, temporaryDurationDays, activationStrategy } = updateRoleDto;

    // Validate user exists and belongs to the correct tenant
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: { tenant: true, roles: { include: { role: true } } },
    });

    if (!user) {
      throw new NotFoundException(`User with id "${userId}" not found`);
    }

    if (user.tenantId !== tenantId) {
      throw new ForbiddenException(`User does not belong to the specified tenant`);
    }

    // Validate roles exist and belong to the same tenant
    const roleIds = roles.map(r => r.roleId);
    const existingRoles = await this.prisma.role.findMany({
      where: { 
        id: { in: roleIds },
        tenantId: tenantId,
      },
    });

    if (existingRoles.length !== roleIds.length) {
      const foundRoleIds = existingRoles.map(r => r.id);
      const missingRoleIds = roleIds.filter(id => !foundRoleIds.includes(id));
      throw new NotFoundException(`Roles not found in tenant: ${missingRoleIds.join(', ')}`);
    }

    // Validate admin permissions and role hierarchy (unless bypassed for emergencies)
    if (!bypassHierarchyCheck) {
      await this.validateRoleHierarchy(updatedByUserId, roleIds, tenantId);
    }

    // Perform the role operation based on type
    let updatedUser;
    
    switch (operation) {
      case UserRoleOperation.ASSIGN:
        updatedUser = await this.assignRoles(userId, roles, updatedByUserId, reason);
        break;
        
      case UserRoleOperation.REMOVE:
        updatedUser = await this.removeRoles(userId, roles, updatedByUserId, reason);
        break;
        
      case UserRoleOperation.REPLACE:
        updatedUser = await this.replaceRoles(userId, roles, updatedByUserId, reason);
        break;
        
      case UserRoleOperation.TEMPORARY_ASSIGN:
        if (!temporaryDurationDays) {
          throw new BadRequestException('temporaryDurationDays is required for TEMPORARY_ASSIGN operation');
        }
        updatedUser = await this.temporaryAssignRoles(userId, roles, temporaryDurationDays, updatedByUserId, reason);
        break;
        
      case UserRoleOperation.INHERIT:
        updatedUser = await this.inheritRoles(userId, roles, updatedByUserId, reason);
        break;
        
      default:
        throw new BadRequestException(`Unsupported operation: ${operation}`);
    }

    // Log the role change event
    await this.eventLog.logEvent('USER_PROFILE_UPDATE', {
      userId: updatedByUserId,
      tenantId: user.tenantId,
      metadata: {
        targetUserId: userId,
        operation,
        roles: roles.map(r => ({ roleId: r.roleId, validFrom: r.validFrom, validUntil: r.validUntil })),
        reason,
        grantedBy,
        notifyUser,
        bypassHierarchyCheck,
        oldRoleIds: user.roles.map(ur => ur.roleId),
        newRoleIds: updatedUser.roles.map(ur => ur.roleId),
        action: 'role_management',
        integrityHash: generateIntegrityHash(`role_change_${userId}_${Date.now()}_${uuidv4().substring(0, 8)}`),
      },
      severity: 'SECURITY',
    });

    // Optionally notify the user about role changes
    if (notifyUser) {
      await this.sendRoleNotification(updatedUser, roles, operation);
    }

    // Invalidate user cache
    await this.invalidateUserCache(userId, tenantId);

    return {
      ...updatedUser,
      message: `Roles ${operation.toLowerCase()}ed successfully`,
    };
  }

  private async assignRoles(userId: string, roles: any[], updatedByUserId: string, reason?: string) {
    return this.prisma.$transaction(async (tx) => {
      // Remove any existing roles with the same role ID to avoid duplicates
      const roleIds = roles.map(r => r.roleId);
      await tx.userRole.deleteMany({
        where: {
          userId,
          roleId: { in: roleIds },
        },
      });

      // Create new role assignments
      const newRoleAssignments = await Promise.all(
        roles.map(async (role) => {
          return tx.userRole.create({
            data: {
              userId,
              roleId: role.roleId,
              createdAt: new Date(),
              validFrom: new Date(role.validFrom || new Date()), // Use provided validFrom or default to now
              validUntil: role.validUntil ? new Date(role.validUntil) : new Date(Date.now() + 100 * 365 * 24 * 60 * 60 * 1000)
            },
            include: { role: true },
          });
        })
      );

      // Update user to reflect changes
      return tx.user.findUnique({
        where: { id: userId },
        include: {
          tenant: true,
          roles: { include: { role: true } },
        },
      });
    });
  }

  private async removeRoles(userId: string, roles: any[], updatedByUserId: string, reason?: string) {
    return this.prisma.$transaction(async (tx) => {
      const roleIds = roles.map(r => r.roleId);
      
      // Remove role assignments
      await tx.userRole.deleteMany({
        where: {
          userId,
          roleId: { in: roleIds },
        },
      });

      // Update user to reflect changes
      return tx.user.findUnique({
        where: { id: userId },
        include: {
          tenant: true,
          roles: { include: { role: true } },
        },
      });
    });
  }

  private async replaceRoles(userId: string, roles: any[], updatedByUserId: string, reason?: string) {
    return this.prisma.$transaction(async (tx) => {
      const roleIds = roles.map(r => r.roleId);
      
      // Remove all existing roles for the user
      await tx.userRole.deleteMany({
        where: { userId },
      });

      // Create new role assignments
      await Promise.all(
        roles.map(async (role) => {
          return tx.userRole.create({
            data: {
              userId,
              roleId: role.roleId,
              createdAt: new Date(),
              validFrom: new Date(role.validFrom || new Date()), 
              validUntil: role.validUntil ? new Date(role.validUntil) : new Date(Date.now() + 100 * 365 * 24 * 60 * 60 * 1000)
            },
          });
        })
      );

      // Update user to reflect changes
      return tx.user.findUnique({
        where: { id: userId },
        include: {
          tenant: true,
          roles: { include: { role: true } },
        },
      });
    });
  }

  private async temporaryAssignRoles(userId: string, roles: any[], durationDays: number, updatedByUserId: string, reason?: string) {
    return this.prisma.$transaction(async (tx) => {
      const now = new Date();
      const validUntil = new Date(now);
      validUntil.setDate(now.getDate() + durationDays);

      // Remove any existing temporary assignments for these roles
      const roleIds = roles.map(r => r.roleId);
      await tx.userRole.deleteMany({
        where: {
          userId,
          roleId: { in: roleIds },
        },
      });

      // Create temporary role assignments with expiration
      await Promise.all(
        roles.map(async (role) => {
          return tx.userRole.create({
            data: {
              userId,
              roleId: role.roleId,
              createdAt: now,
              validFrom: now,
              validUntil: validUntil,
            },
          });
        })
      );

      // Update user to reflect changes
      return tx.user.findUnique({
        where: { id: userId },
        include: {
          tenant: true,
          roles: { include: { role: true } },
        },
      });
    });
  }

  private async inheritRoles(userId: string, roles: any[], updatedByUserId: string, reason?: string) {
    return this.prisma.$transaction(async (tx) => {
      const roleIds = roles.map(r => r.roleId);
      
      // Get parent roles and their inheritance rules
      const parentRoles = await tx.role.findMany({
        where: {
          id: { in: roleIds },
          parentRoleId: { not: null },
        },
        include: {
          parentRole: true,
        },
      });

      // Create role assignments including inherited roles
      const allRoleIds = [...new Set(roleIds)]; // Use Set to avoid duplicates
      parentRoles.forEach(parent => {
        if (parent.parentRole && !allRoleIds.includes(parent.parentRole.id)) {
          allRoleIds.push(parent.parentRole.id);
        }
      });

      // Remove existing roles and assign new ones with inheritance
      await tx.userRole.deleteMany({
        where: { userId },
      });

      await Promise.all(
        allRoleIds.map(async (roleId) => {
          return tx.userRole.create({
            data: {
              userId,
              roleId,
              createdAt: new Date(),
              validFrom: new Date(), // Set to current time
              validUntil: new Date(Date.now() + 100 * 365 * 24 * 60 * 60 * 1000),
            },
          });
        })
      );

      // Update user to reflect changes
      return tx.user.findUnique({
        where: { id: userId },
        include: {
          tenant: true,
          roles: { include: { role: true } },
        },
      });
    });
  }

  private async validateRoleHierarchy(updatedByUserId: string, targetRoleIds: string[], tenantId: string) {
    // Validate that the user making the change has permission to assign these roles
    const updaterRoles = await this.prisma.userRole.findMany({
      where: { 
        userId: updatedByUserId,
        role: { tenantId } // Ensure roles are from the same tenant
      },
      include: { role: true },
    });

    if (updaterRoles.length === 0) {
      throw new ForbiddenException('User has no roles and cannot manage roles');
    }

    // Check if updater has admin or system role
    const hasAdminRole = updaterRoles.some(ur => 
      ur.role.isSystem || 
      ['ADMIN', 'SUPER_ADMIN', 'SYSTEM_ADMIN'].includes(ur.role.name.toUpperCase())
    );

    if (!hasAdminRole) {
      throw new ForbiddenException('Insufficient permissions to manage roles');
    }

    // Additional validation could include checking if target roles are system roles
    // or have special restrictions
    const targetRoles = await this.prisma.role.findMany({
      where: { id: { in: targetRoleIds } },
    });

    const systemRoles = targetRoles.filter(role => role.isSystem);
    if (systemRoles.length > 0 && !hasAdminRole) {
      throw new ForbiddenException('Cannot assign system roles without admin privileges');
    }
  }

  private async sendRoleNotification(user: any, roles: any[], operation: string) {
    // Implementation for sending notifications to users about role changes
    // This could be email, push notification, etc.
    this.logger.log(`Notification sent to user ${user.id} about role ${operation}: ${roles.map(r => r.roleId).join(', ')}`);
  }

  async getAuditEvents(
    limit = 50,
    offset = 0,
    type?: string,
    userId?: string,
    startDate?: Date,
    endDate?: Date,
    severity?: string,
    tenantId?: string,
    action?: string,
  ) {
    if (limit < 1 || limit > 100) {
      throw new BadRequestException('Limit must be between 1 and 100');
    }
    if (offset < 0) {
      throw new BadRequestException('Offset cannot be negative');
    }

    return this.eventLog.queryEvents({
      type: type as any,
      userId,
      startDate,
      endDate,
      severity: severity as any,
      tenantId,
      limit,
      offset,
    });
  }

  async getRoleAnalytics(tenantId: string) {
    // Validate tenant exists
    const tenant = await this.prisma.tenant.findUnique({
      where: { id: tenantId },
      select: { id: true },
    });

    if (!tenant) {
      throw new NotFoundException(`Tenant with id "${tenantId}" not found`);
    }

    const [roleStats, userRoleStats, permissionStats] = await Promise.all([
      this.prisma.role.groupBy({
        by: ['name'],
        where: { tenantId },
        _count: true,
        _avg: {
          priority: true,
        },
      }),
      this.prisma.userRole.aggregate({
        where: { role: { tenantId } },
        _count: {
          id: true,
          userId: true,
          roleId: true,
        },
              }),
      this.prisma.rolePermission.aggregate({
        where: { role: { tenantId } },
        _count: {
          id: true,
        },
      }),
    ]);

    return {
      roleDistribution: roleStats,
      userRoleStats,
      permissionStats,
      timestamp: new Date(),
    };
  }

  async getTenantUserStats(tenantId: string) {
    // Validate tenant exists
    const tenant = await this.prisma.tenant.findUnique({
      where: { id: tenantId },
      select: { id: true },
    });

    if (!tenant) {
      throw new NotFoundException(`Tenant with id "${tenantId}" not found`);
    }

    const [totalUsers, activeUsers, roleDistribution, securityStats] = await Promise.all([
      this.prisma.user.count({ where: { tenantId } }),
      this.prisma.user.count({ 
        where: { 
          tenantId,
          roles: {
            some: {
              role: {
                isActive: true,
              }
            }
          }
        } 
      }),
      this.prisma.role.groupBy({
        by: ['name'],
        where: { tenantId },
        _count: true,
      }),
      this.prisma.event.count({
        where: {
          tenantId,
          severity: 'SECURITY',
          createdAt: {
            gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000), // Last 30 days
          },
        },
      }),
    ]);

    return {
      totalUsers,
      activeUsers,
      roleDistribution,
      securityEventsLast30Days: securityStats,
      timestamp: new Date(),
    };
  }

  async bulkUpdateUserRoles(
    userIds: string[], 
    roleIds: string[], 
    operation: 'ASSIGN' | 'REMOVE' | 'REPLACE',
    updatedByUserId: string,
    reason?: string,
  ) {
    if (userIds.length > 100) {
      throw new BadRequestException('Bulk operations are limited to 100 users at a time');
    }

    if (userIds.length === 0) {
      throw new BadRequestException('User IDs array cannot be empty');
    }

    // Validate all users exist and belong to same tenant
    const users = await this.prisma.user.findMany({
      where: { id: { in: userIds } },
      select: { id: true, tenantId: true },
    });

    if (users.length !== userIds.length) {
      const foundUserIds = users.map(u => u.id);
      const missingUserIds = userIds.filter(id => !foundUserIds.includes(id));
      throw new NotFoundException(`Users not found: ${missingUserIds.join(', ')}`);
    }

    // Get the tenant ID from the first user (assuming all users are in same tenant for bulk op)
    const tenantId = users[0].tenantId;
    
    // Validate all users belong to same tenant
    const uniqueTenantIds = [...new Set(users.map(u => u.tenantId))];
    if (uniqueTenantIds.length > 1) {
      throw new BadRequestException('All users must belong to the same tenant for bulk operations');
    }

    // Validate roles exist in tenant
    const roles = await this.prisma.role.findMany({
      where: { 
        id: { in: roleIds },
        tenantId: tenantId,
      },
      select: { id: true },
    });

    if (roles.length !== roleIds.length) {
      const foundRoleIds = roles.map(r => r.id);
      const missingRoleIds = roleIds.filter(id => !foundRoleIds.includes(id));
      throw new NotFoundException(`Roles not found in tenant: ${missingRoleIds.join(', ')}`);
    }

    const results = await Promise.allSettled(
      userIds.map(userId => 
        this.updateUserRole({
          operation: operation as UserRoleOperation,
          userId,
          tenantId,
          roles: roleIds.map(roleId => ({ roleId })),
          reason,
        } as UpdateUserRoleDto, updatedByUserId)
      )
    );

    const successfulUpdates = results.filter(r => r.status === 'fulfilled').length;
    const failedUpdates = results.filter(r => r.status === 'rejected').length;

    await this.eventLog.logEvent('USER_PROFILE_UPDATE', {
      userId: updatedByUserId,
      tenantId, // Specific tenant for bulk operation
      metadata: {
        action: 'bulk_role_update',
        totalUsers: userIds.length,
        successfulUpdates,
        failedUpdates,
        operation,
        roleIds,
        reason,
      },
      severity: 'INFO',
    });

    return {
      totalUsers: userIds.length,
      successfulUpdates,
      failedUpdates,
      results: results.map((result, index) => ({
        userId: userIds[index],
        success: result.status === 'fulfilled',
        error: result.status === 'rejected' ? (result.reason as Error).message : undefined,
      })),
    };
  }

  private async invalidateUserCache(userId: string, tenantId: string) {
    // Invalidate user-related cache entries
    await this.redis.del(`user:${userId}:details`);
    await this.redis.del(`user:${userId}:roles`);
    await this.redis.del(`tenant:${tenantId}:users:*`); // Invalidate tenant user lists
  }

  async getUserRoleDetails(userId: string) {
    const cacheKey = `user:${userId}:roles`;
    const cached = await this.redis.get(cacheKey);
    
    if (cached) {
      return JSON.parse(cached);
    }

    const userWithRoles = await this.prisma.user.findUnique({
      where: { id: userId },
      include: {
        roles: {
          include: {
            role: {
              include: {
                permissions: {
                  include: {
                    permission: true,
                  },
                },
              },
            },
          },
        },
      },
    });

    if (!userWithRoles) {
      throw new NotFoundException(`User with id "${userId}" not found`);
    }

    const result = {
      userId: userWithRoles.id,
      name: userWithRoles.name,
      email: userWithRoles.email,
      roles: userWithRoles.roles.map(ur => ({
        roleId: ur.role.id,
        roleName: ur.role.name,
        roleDescription: ur.role.description,
        permissions: ur.role.permissions.map(rp => ({
          permissionId: rp.permission.id,
          permissionName: rp.permission.name,
          resource: rp.permission.resource,
          action: rp.permission.action,
          allowed: rp.allowed,
        })),
      })),
    };

    // Cache for 15 minutes
    await this.redis.setex(cacheKey, 900, JSON.stringify(result));

    return result;
  }
}