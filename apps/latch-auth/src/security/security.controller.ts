// src/security/security.controller.ts
import {
  Controller,
  Get,
  UseGuards,
  HttpCode,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { TenantGuard } from '../auth/guards/tenant.guard';
import { RolesGuard } from '../auth/guards/roles.guard'; // ✅ Use base RolesGuard
import { AdminOnly } from '../auth/decorators/admin-only.decorator'; // ✅ Static decorator

import { SecurityMonitoringService } from './security-monitor.service';
import { EventLogService } from '../events/event.service';
import { ChainVerificationResult } from '../events/event.types';
@Controller('security')
@UseGuards(JwtAuthGuard, TenantGuard, RolesGuard) // ✅ Full auth chain
export class SecurityController {
  private readonly logger = new Logger(SecurityController.name);

  constructor(
    private readonly monitor: SecurityMonitoringService,
    private readonly eventLog: EventLogService,
  ) {}

  /**
   * GET /v1/security/status
   *
   * Admin-only security dashboard endpoint.
   * Leverages existing RolesGuard for:
   * - Tenant-scoped ADMIN role validation
   * - Full audit logging (granted/denied)
   * - IP/user-agent tracking
   * - Integrity chain metadata
   */
  @Get('status')
  @AdminOnly() // ✅ Clean, static, no mutation, no inheritance
  @HttpCode(HttpStatus.OK)
  async getSecurityStatus() {
    try {
      const threatSummary =
        typeof this.monitor.getSecurityStatus === 'function'
          ? this.monitor.getSecurityStatus()
          : { info: 'monitor.getSecurityStatus() not available' };

      // const chainResult = await this.eventLog.verifyChain().catch((err) => {
      //   this.logger.error('verifyChain() failed', err);
      //   return { valid: false, error: (err as Error).message ?? String(err) };
      // });

      let chainResult: ChainVerificationResult;

      try {
        chainResult = await this.eventLog.verifyChain();
      } catch (err) {
        chainResult = {
          valid: false,
          error: (err as Error).message || 'Unknown error',
        };
      }

      const from = new Date(Date.now() - 60 * 60 * 1000).toISOString();
      const eventTypesToReport = [
        'TOKEN_REUSE',
        'SECURITY_CSRF_MISMATCH',
        'AUTH_JWT_FAILURE',
        'REFRESH_FAILED',
        'OTP_FAILED',
      ] as const;

      const recentCounts: Record<string, number | null> = {};
      for (const t of eventTypesToReport) {
        try {
          const paginated = await this.eventLog.findByType(t, 1, 0, from);
          recentCounts[t] = paginated.meta?.total ?? null;
        } catch (err) {
          this.logger.warn(
            `Failed to count events for ${t}`,
            (err as Error).message,
          );
          recentCounts[t] = null;
        }
      }

      const chain =
        'error' in chainResult
          ? {
              valid: chainResult.valid, // always false
              total: null,
              brokenIndex: null,
              error: chainResult.error,
            }
          : 'brokenIndex' in chainResult
            ? {
                valid: chainResult.valid, // always false
                total: chainResult.total,
                brokenIndex: chainResult.brokenIndex,
                error: null,
              }
            : {
                // Must be ChainVerificationValid
                valid: chainResult.valid, // always true
                total: chainResult.total,
                brokenIndex: null,
                error: null,
              };

      return {
        ok: true,
        timestamp: new Date().toISOString(),
        threatSummary,
        chain,
        recentCounts,
      };

      // return {
      //   ok: true,
      //   timestamp: new Date().toISOString(),
      //   threatSummary,
      //   chain: {
      //     valid: !!chainResult.valid,
      //     total: chainResult.total ?? null,
      //     brokenIndex: chainResult.brokenIndex ?? null,
      //     error: (chainResult as any).error ?? null,
      //   },
      //   recentCounts,
      // };
    } catch (err) {
      this.logger.error('getSecurityStatus failed', err);
      return {
        ok: false,
        error: (err as Error).message ?? String(err),
      };
    }
  }
}

// #TODO — Phase 2 Hardening & Future Extensions
// 1. Cache last verified chain result in-memory (5–10min TTL) to reduce DB load.
// 2. Add Prometheus metrics exporter for threatSummary counters.
// 3. Extend verifyChain() to support partial verification window (last N events).
// 4. Add /v1/security/chain/verify endpoint (manual admin trigger).
// 5. Rotate signingSecret automatically via Key Management (monthly schedule).
// 6. Implement optional external tamper-evident audit stream (Kafka or append-only log).
// 7. Integrate SecurityMonitoringService alerts with centralized SIEM or PagerDuty.
// 8. Add Zod schema validation for EventLog metadata payloads.
// 9. Add debounce/rate-limit per event type to prevent spam flooding (DoS mitigation).
// 10. Implement SDK layer that securely wraps EventLogService calls (for microservices).
