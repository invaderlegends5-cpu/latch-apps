//src/maintenance/session-cleaner.service.ts
import { Injectable, Logger } from '@nestjs/common';
import { Cron } from '@nestjs/schedule';
import { PrismaService } from '../prisma/prisma.service';
import { EventLogService } from '../events/event.service';
import { SecurityConfig } from '../config/security.config';

@Injectable()
export class SessionCleanerService {
  private readonly logger = new Logger(SessionCleanerService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly eventLogService: EventLogService,
  ) {}

  @Cron(SecurityConfig.CLEANUP_CRON_EXPRESSION)
  async pruneExpiredSessions() {
    const now = new Date();
    const retentionMs =
      SecurityConfig.REFRESH_TOKEN_RETENTION_DAYS * 24 * 60 * 60 * 1000;

    this.logger.debug('Running scheduled session and token cleanup');

    // 1️⃣ Revoke sessions that expired but are still marked active
    const expiredSessions = await this.prisma.session.updateMany({
      where: { expiresAt: { lt: now }, revoked: false },
      data: { revoked: true },
    });

    if (expiredSessions.count > 0) {
      await this.eventLogService.logEvent('SESSION_REVOKE_ALL', {
        userId: null,
        tenantId: null,
        metadata: {
          reason: 'scheduled_prune',
          revokedCount: expiredSessions.count,
        },
        severity: 'INFO',
      });
    }

    // 2️⃣ Delete old used refresh tokens
    const deletedTokens = await this.prisma.usedRefreshToken.deleteMany({
      where: { usedAt: { lt: new Date(Date.now() - retentionMs) } },
    });

    if (deletedTokens.count > 0) {
      await this.eventLogService.logEvent('USED_REFRESH_TOKEN_PURGE', {
        userId: null,
        tenantId: null,
        metadata: {
          reason: 'retention_expired',
          deletedCount: deletedTokens.count,
          retentionDays: SecurityConfig.REFRESH_TOKEN_RETENTION_DAYS,
        },
        severity: 'INFO',
      });
    }

    this.logger.debug(
      `Cleanup complete: ${expiredSessions.count} expired sessions revoked, ${deletedTokens.count} old refresh tokens purged.`,
    );
  }
   // --- NEW: Cron job for removing expired temporary roles ---
   @Cron('0 * * * *') // Run every hour, adjust as needed
   async removeExpiredTemporaryRoles() {
     const now = new Date();
     this.logger.debug('Running scheduled temporary role cleanup');
 
     // Find user roles that have expired (validUntil < now) and were created for temporary assignment
     // You might need to add a field to distinguish temporary assignments if not already clear from validUntil
     // For now, assuming any role with a validUntil in the past is temporary and should be removed
     const expiredTempRoles = await this.prisma.userRole.findMany({
       where: {
         validUntil: {
           lt: now, // Less than now means it has expired
         },
       },
       select: {
         id: true, // The ID of the userRole entry to delete
         userId: true, // Needed for logging
         roleId: true, // Needed for logging
         validUntil: true, // For logging
       },
     });
 
     if (expiredTempRoles.length > 0) {
       const userIds = [...new Set(expiredTempRoles.map(ur => ur.userId))]; // Get unique user IDs for cache invalidation
 
       // Delete the expired userRole entries
       const deletedRoles = await this.prisma.userRole.deleteMany({
         where: {
           id: { in: expiredTempRoles.map(ur => ur.id) },
         },
       });
 
       this.logger.log(`Removed ${deletedRoles.count} expired temporary role assignments.`);
 
       // Log the event for audit trail
       for (const role of expiredTempRoles) {
         await this.eventLogService.logEvent('USER_PROFILE_UPDATE', {
           userId: role.userId, // Or SYSTEM user ID
           tenantId: (await this.prisma.user.findUnique({ where: { id: role.userId }, select: { tenantId: true } }))?.tenantId || null,
           metadata: {
             action: 'temporary_role_expired',
             reason: 'Scheduled cleanup removed expired temporary role',
             roleId: role.roleId,
             expiredAt: role.validUntil,
           },
           severity: 'INFO', // Could be 'SECURITY' if temporary roles are sensitive
         });
       }
 
       // Invalidate cache for affected users (if applicable)
       // Example: Assuming a method exists or you implement one
       // await Promise.all(userIds.map(userId => this.invalidateUserCache(userId)));
 
     } else {
       this.logger.debug('No expired temporary roles found.');
     }
   }
   // --- END NEW ---
}
