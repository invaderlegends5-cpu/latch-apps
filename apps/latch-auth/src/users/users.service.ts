// import { Injectable } from '@nestjs/common';
// import { PrismaService } from '../prisma/prisma.service';

// @Injectable()
// export class UsersService {
//   constructor(private prisma: PrismaService) {}

//   async findById(id: string) {
//     return this.prisma.user.findUnique({ where: { id }});
//   }

//   async listForTenant(tenantId: string) {
//     return this.prisma.user.findMany({ where: { tenantId }});
//   }
// }

// users.service.ts
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { EventLogService } from '../events/event.service';

@Injectable()
export class UsersService {
  constructor(
    private prisma: PrismaService,
    private eventLogService: EventLogService, // ✅ Added EventLogService
  ) {}

  async findById(id: string) {
    return this.prisma.user.findUnique({ where: { id } });
  }

  // ✅ Enhanced with security validation and logging
  async findByIdWithAccessCheck(
    requestingUserId: string,
    targetUserId: string,
    tenantId: string,
    ipAddress?: string | null,
    userAgent?: string | null,
  ) {
    // Prevent users from accessing other tenants' data
    if (requestingUserId !== targetUserId) {
      await this.eventLogService.logEvent('USER_DATA_ACCESS_ATTEMPT', {
        userId: requestingUserId,
        tenantId,
        metadata: {
          targetUserId,
          reason: 'cross_user_access',
        },
        ipAddress,
        userAgent,
      });

      // In a real app, you'd check specific permissions here //
      // For now, only allow self-access for security
      throw new UnauthorizedException('Access denied');
    }

    const user = await this.prisma.user.findUnique({
      where: { id: targetUserId, tenantId }, // ✅ Added tenantId for security
    });

    if (user) {
      await this.eventLogService.logEvent('USER_DATA_ACCESSED', {
        userId: requestingUserId,
        tenantId,
        metadata: {
          targetUserId,
          accessType: 'self_access',
        },
        ipAddress,
        userAgent,
      });
    }

    return user;
  }

  // ✅ Enhanced with tenant isolation and logging
  async listForTenant(
    requestingUserId: string,
    tenantId: string,
    ipAddress?: string | null,
    userAgent?: string | null,
  ) {
    // Log the access attempt
    await this.eventLogService.logEvent('USER_LIST_ACCESSED', {
      userId: requestingUserId,
      tenantId,
      metadata: {
        action: 'list_users_for_tenant',
      },
      ipAddress,
      userAgent,
    });

    // ✅ Security: Ensure the requesting user belongs to this tenant
    const requestingUser = await this.prisma.user.findUnique({
      where: { id: requestingUserId, tenantId },
    });

    if (!requestingUser) {
      await this.eventLogService.logEvent('USER_LIST_ACCESS_DENIED', {
        userId: requestingUserId,
        tenantId,
        metadata: {
          reason: 'user_not_in_tenant',
        },
        ipAddress,
        userAgent,
      });
      throw new UnauthorizedException('User does not belong to this tenant');
    }

    return this.prisma.user.findMany({
      where: { tenantId },
      select: {
        id: true,
        phone: true,
        // Exclude sensitive fields like passwords, tokens, etc.
      },
    });
  }

  // ✅ New: Secure profile update with logging
  async updateProfile(
    userId: string,
    tenantId: string,
    updates: { phone?: string },
    ipAddress?: string | null,
    userAgent?: string | null,
  ) {
    // Validate phone format if provided
    if (updates.phone) {
      if (!/^\+?[1-9]\d{1,14}$/.test(updates.phone)) {
        await this.eventLogService.logEvent('USER_PROFILE_UPDATE_FAILED', {
          userId,
          tenantId,
          metadata: {
            reason: 'invalid_phone_format',
            attemptedField: 'phone',
          },
          ipAddress,
          userAgent,
        });
        throw new UnauthorizedException('Invalid phone number format');
      }
    }

    await this.eventLogService.logEvent('USER_PROFILE_UPDATE', {
      userId,
      tenantId,
      metadata: {
        updatedFields: Object.keys(updates),
      },
      ipAddress,
      userAgent,
    });

    return this.prisma.user.update({
      where: { id: userId, tenantId }, // ✅ Tenant isolation
      data: updates, // ✅ Use 'data' property
    });
  }
}
