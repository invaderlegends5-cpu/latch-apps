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
}
