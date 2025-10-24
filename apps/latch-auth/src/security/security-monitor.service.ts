// src/security/security-monitoring.service.ts
import {
  Injectable,
  Logger,
  OnModuleInit,
  OnModuleDestroy,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { EventLogService } from '../events/event.service';
import { SecurityEvent, EventType } from '../events/event.types';
import * as Sentry from '@sentry/node';
import axios from 'axios';

@Injectable()
export class SecurityMonitoringService
  implements OnModuleInit, OnModuleDestroy
{
  private readonly logger = new Logger(SecurityMonitoringService.name);

  private webhookUrl?: string;
  private windowMinutes: number;
  private thresholds: Partial<Record<EventType, number>> = {
    TOKEN_REUSE: 5,
    SECURITY_CSRF_MISMATCH: 3,
    AUTH_JWT_FAILURE: 10,
    REFRESH_FAILED: 5,
    OTP_FAILED: 5,
  };

  private eventBuckets = new Map<string, number[]>();
  private cleanupInterval: NodeJS.Timeout;

  constructor(
    private readonly events: EventLogService,
    private readonly config: ConfigService,
  ) {
    this.webhookUrl = this.config.get<string>('SECURITY_ALERT_WEBHOOK_URL');
    if (this.webhookUrl && !this.webhookUrl.startsWith('https://')) {
      this.logger.warn(
        'SECURITY_ALERT_WEBHOOK_URL should use HTTPS for security',
      );
    }

    this.windowMinutes = this.config.get<number>(
      'SECURITY_ALERT_WINDOW_MINUTES',
      60,
    );

    Object.keys(this.thresholds).forEach((key) => {
      const envValue = this.config.get<number>(
        `SECURITY_ALERT_THRESHOLD_${key}`,
      );
      if (envValue && key in this.thresholds) {
        this.thresholds[key as EventType] = envValue;
      }
    });
  }

  onModuleInit() {

    if (!this.events?.event$) {
      if (process.env.NODE_ENV !== 'production') {
        this.logger.warn('EventLogService not initialized, skipping subscription');
      }
      return;
    }
    
    this.events.event$.subscribe((event: SecurityEvent) =>
      this.handleEvent(event),
    );

    this.cleanupInterval = setInterval(
      () => this.pruneOldEntries(),
      5 * 60 * 1000,
    );

    this.logger.log('SecurityMonitoringService initialized');
  }

  onModuleDestroy() {
    if (this.cleanupInterval) clearInterval(this.cleanupInterval);
  }

  private handleEvent(event: SecurityEvent) {
    // Skip events without integrity hash (shouldn't happen in production)
    if (!event.integrityHash) {
      this.logger.warn(
        `Event ${event.id} missing integrityHash, skipping monitoring`,
      );
      return;
    }

    const key = this.getAggregationKey(event);
    if (!key) return;

    const now = Date.now();
    const bucketKey = `${event.type}:${key}`;
    const timestamps = this.eventBuckets.get(bucketKey) ?? [];
    timestamps.push(now);
    this.eventBuckets.set(bucketKey, timestamps);

    this.evaluateThreshold(event.type, bucketKey, timestamps);
    this.limitBuckets();
  }

  private getAggregationKey(event: SecurityEvent): string | null {
    switch (event.type) {
      case 'TOKEN_REUSE':
      case 'REFRESH_FAILED':
        return event.userId ?? null;
      case 'SECURITY_CSRF_MISMATCH':
      case 'AUTH_JWT_FAILURE':
      case 'OTP_FAILED':
        return event.ipAddress ?? null;
      default:
        this.logger.warn(`Unknown event type for aggregation: ${event.type}`);
        return null;
    }
  }

  private evaluateThreshold(
    type: EventType,
    bucketKey: string,
    timestamps: number[],
  ) {
    const cutoff = Date.now() - this.windowMinutes * 60 * 1000;
    const recent = timestamps.filter((t) => t >= cutoff);
    this.eventBuckets.set(bucketKey, recent);

    const limit = this.thresholds[type] ?? 0;
    if (recent.length > limit) {
      this.triggerAlert(type, bucketKey, recent.length).catch((err) => {
        this.logger.error(`Security alert delivery failed for ${type}:`, err);
      });
      this.eventBuckets.set(bucketKey, []);
    }
  }

  private pruneOldEntries() {
    const cutoff = Date.now() - this.windowMinutes * 60 * 1000;
    for (const [key, timestamps] of this.eventBuckets) {
      const recent = timestamps.filter((t) => t >= cutoff);
      if (recent.length === 0) this.eventBuckets.delete(key);
      else this.eventBuckets.set(key, recent);
    }
  }

  private limitBuckets(maxBuckets = 10_000) {
    if (this.eventBuckets.size > maxBuckets) {
      this.logger.warn(
        `eventBuckets exceeded max ${maxBuckets}, trimming oldest entries`,
      );
      const keys = Array.from(this.eventBuckets.keys()).slice(
        0,
        this.eventBuckets.size - maxBuckets,
      );
      keys.forEach((k) => this.eventBuckets.delete(k));
    }
  }

  private async postWithRetry(url: string, data: any, maxRetries = 2) {
    for (let i = 0; i <= maxRetries; i++) {
      try {
        return await axios.post(url, data);
      } catch (err: any) {
        this.logger.error(
          `Webhook attempt ${i + 1}/${maxRetries + 1} failed: ${err.message}`,
        );
        if (i === maxRetries) throw err;
        await new Promise((res) => setTimeout(res, 1000 * 2 ** i));
      }
    }
  }

  private async triggerAlert(type: EventType, key: string, count: number) {
    const message = `⚠️ Security alert: ${count} ${type} events detected`;

    this.logger.warn(message);
    Sentry.captureMessage(`[${type}] ${message}`, 'warning');

    if (this.webhookUrl) {
      await this.postWithRetry(this.webhookUrl, {
        type,
        key,
        count,
        windowMinutes: this.windowMinutes,
      });
    }
  }

  public getSecurityStatus(): Record<string, number> {
    const status: Record<string, number> = {};
    for (const [bucketKey, timestamps] of this.eventBuckets) {
      const [type] = bucketKey.split(':');
      status[type] = (status[type] || 0) + timestamps.length;
    }
    return status;
  }
}
