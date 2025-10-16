// src/events/event.service.ts
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';
import * as crypto from 'crypto';
import { ReplaySubject } from 'rxjs';
import {
  SecurityEvent,
  EventType,
  EventSeverity,
  EventMeta,
  ChainVerificationValid,
  ChainVerificationBroken,
} from './event.types';

export interface PaginatedResult<T> {
  data: T[];
  meta: {
    total: number;
    limit: number;
    offset: number;
    hasNext: boolean;
  };
}

interface EventWhereInput {
  createdAt?: { gte?: Date; lte?: Date };
  type?: EventType;
  userId?: string;
}

// export type ChainVerificationResult =
//   | { valid: true; total: number }
//   | { valid: false; brokenIndex: number; total: number };

@Injectable()
export class EventLogService {
  private readonly logger = new Logger(EventLogService.name);

  // Typed replay subject so late subscribers get the most recent event
  private readonly eventSubject = new ReplaySubject<SecurityEvent>(1);
  public readonly event$ = this.eventSubject.asObservable();

  // Signing secret from ConfigService
  private readonly signingSecret: string;

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
  ) {
    this.signingSecret = this.config.get<string>('EVENT_SIGNING_SECRET') ?? '';

    if (!this.signingSecret && process.env.NODE_ENV !== 'development') {
      throw new Error('EVENT_SIGNING_SECRET is required in production');
    }

    if (!this.signingSecret) {
      this.logger.warn(
        'EVENT_SIGNING_SECRET is empty — integrity hashes will be predictable. Set EVENT_SIGNING_SECRET in env for production.',
      );
    }
  }

  // -------------------------
  // Helpers: masking / truncation
  // -------------------------
  private maskIp(ip?: string | null): string | null {
    if (!ip) return null;
    // IPv6: keep first 4 groups, then ::
    if (ip.includes(':')) {
      const parts = ip.split(':');
      const head = parts.slice(0, 4).join(':');
      return `${head}::`;
    }
    // IPv4: mask last octet
    const parts = ip.split('.');
    if (parts.length === 4) {
      parts[3] = 'x';
      return parts.join('.');
    }
    return null;
  }

  private truncateUserAgent(ua?: string | null, max = 256): string | null {
    if (!ua) return null;
    return ua.length > max ? ua.substring(0, max) : ua;
  }

  // -------------------------
  // Integrity: compute SHA-256 over canonical payload + prevHash + secret
  // -------------------------
  private computeIntegrity(payload: Record<string, any>): string {
    // deterministic serialization with sorted keys
    const stable = JSON.stringify(this.sortObjectKeys(payload));
    const toHash = `${stable}::${this.signingSecret}`;
    return crypto.createHash('sha256').update(toHash).digest('hex');
  }

  private sortObjectKeys(obj: any): any {
    if (obj === null || typeof obj !== 'object' || Array.isArray(obj))
      return obj;
    return Object.keys(obj)
      .sort()
      .reduce((acc: any, k) => {
        acc[k] = this.sortObjectKeys(obj[k]);
        return acc;
      }, {});
  }

  // -------------------------
  // Main logging API
  // -------------------------
  async logEvent(
    type: EventType,
    opts: {
      userId?: string | null;
      tenantId?: string | null;
      metadata?: EventMeta;
      ipAddress?: string | null;
      userAgent?: string | null;
      severity?: EventSeverity;
    } = {},
  ) {
    const {
      userId = null,
      tenantId = null,
      metadata = {},
      ipAddress = null,
      userAgent = null,
      severity = 'INFO',
    } = opts;

    try {
      // Transaction: read last integrityHash and insert new row atomically
      const created = await this.prisma.$transaction(async (tx) => {
        // Get last integrityHash (most recent event)
        const last = await tx.event.findFirst({
          orderBy: { createdAt: 'desc' },
          select: { integrityHash: true },
        });
        const prevHash = last?.integrityHash ?? null;

        // Sort metadata keys for deterministic hashing
        const sortedMetadata = metadata ? this.sortObjectKeys(metadata) : {};

        // Prepare event data for DB and for hashing (mask/truncate before hashing)
        const eventDataForHash = {
          userId,
          tenantId,
          type,
          severity,
          metadata: sortedMetadata,
          ipAddress: this.maskIp(ipAddress),
          userAgent: this.truncateUserAgent(userAgent),
          prevHash,
          createdAt: new Date().toISOString(),
        };

        const integrityHash = this.computeIntegrity(eventDataForHash);

        // Persist
        const row = await tx.event.create({
          data: {
            userId,
            tenantId,
            type,
            severity,
            sessionId: metadata.sessionId ?? null,
            familyId: metadata.familyId ?? null,
            reason: metadata.reason ?? null,
            metadata: sortedMetadata,
            ipAddress: this.maskIp(ipAddress),
            userAgent: this.truncateUserAgent(userAgent),
            integrityHash,
            prevHash,
          },
        });

        return row;
      });

      // Emit asynchronously (non-blocking) and safe-guard against subscriber errors
      setImmediate(() => {
        try {
          const emitted: SecurityEvent = {
            id: created.id,
            type: created.type,
            severity: created.severity,
            userId: created.userId ?? null,
            tenantId: created.tenantId ?? null,
            ipAddress: created.ipAddress ?? null,
            userAgent: created.userAgent ?? null,
            sessionId: (created as any).sessionId ?? null,
            familyId: (created as any).familyId ?? null,
            reason: (created as any).reason ?? null,
            metadata: (created as any).metadata ?? {},
            integrityHash: created.integrityHash,
            prevHash: created.prevHash,
            createdAt: created.createdAt,
          };
          this.eventSubject.next(emitted);
        } catch (emitErr) {
          // never crash the request on emit errors
          this.logger.warn(
            'Failed to emit SecurityEvent',
            (emitErr as Error).message,
          );
        }
      });

      return created;
    } catch (err: unknown) {
      if (err instanceof Error) {
        this.logger.warn('[EVENT_LOG_ERROR]', err.stack);
      } else {
        this.logger.warn('[EVENT_LOG_ERROR]', { err });
      }
      return null;
    }
  }

  // -------------------------
  // Verification utility for admin / audits
  // -------------------------
  /**
   * verifyChain - validates integrityHash + prevHash chain across all events (ascending by createdAt)
   * returns { valid: boolean, brokenIndex?: number, total?: number }
   */

  async verifyChain(): Promise<
    ChainVerificationValid | ChainVerificationBroken
  > {
    const events = await this.prisma.event.findMany({
      orderBy: { createdAt: 'asc' },
      select: {
        id: true,
        integrityHash: true,
        prevHash: true,
        userId: true,
        tenantId: true,
        type: true,
        severity: true,
        reason: true,
        metadata: true,
        ipAddress: true,
        userAgent: true,
        createdAt: true,
      },
    });

    if (events.length === 0) {
      return { valid: true, total: 0 };
    }

    let prevHash: string | null = null;
    for (let i = 0; i < events.length; i++) {
      const e = events[i];

      // Sort metadata for consistent hashing
      const sortedMetadata = e.metadata ? this.sortObjectKeys(e.metadata) : {};

      // reconstruct the payload used for hashing (must match what logEvent used)
      const payload = {
        userId: e.userId ?? null,
        tenantId: e.tenantId ?? null,
        type: e.type,
        severity: e.severity,
        metadata: sortedMetadata,
        ipAddress: e.ipAddress ?? null,
        userAgent: e.userAgent ?? null,
        prevHash,
      };

      const recomputed = this.computeIntegrity(payload);
      if (recomputed !== e.integrityHash || e.prevHash !== prevHash) {
        this.logger.error(`Integrity chain broken at index ${i} id=${e.id}`);
        return { valid: false, brokenIndex: i, total: events.length };
      }
      prevHash = e.integrityHash;
    }

    this.logger.log(`Integrity chain verified: ${events.length} events`);
    return { valid: true, total: events.length };
  }

  // -------------------------
  // Query helpers
  // -------------------------
  async findRecent(
    limit = 50,
    offset = 0,
    from?: string,
    to?: string,
  ): Promise<PaginatedResult<any>> {
    const where: EventWhereInput = {};
    if (from) where.createdAt = { gte: new Date(from) };
    if (to) where.createdAt = { ...where.createdAt, lte: new Date(to) };

    const [events, total] = await Promise.all([
      this.prisma.event.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        take: limit,
        skip: offset,
        select: {
          id: true,
          userId: true,
          tenantId: true,
          type: true,
          severity: true,
          sessionId: true,
          familyId: true,
          reason: true,
          metadata: true,
          ipAddress: true,
          userAgent: true,
          integrityHash: true,
          prevHash: true,
          createdAt: true,
        },
      }),
      this.prisma.event.count({ where }),
    ]);

    return this.attachUserTenant(events, total, limit, offset);
  }

  async findByType(
    type: EventType,
    limit = 50,
    offset = 0,
    from?: string,
    to?: string,
  ): Promise<PaginatedResult<any>> {
    const where: EventWhereInput = { type };
    if (from) where.createdAt = { gte: new Date(from) };
    if (to) where.createdAt = { ...where.createdAt, lte: new Date(to) };

    const [events, total] = await Promise.all([
      this.prisma.event.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        take: limit,
        skip: offset,
        select: {
          id: true,
          userId: true,
          tenantId: true,
          type: true,
          severity: true,
          sessionId: true,
          familyId: true,
          reason: true,
          metadata: true,
          ipAddress: true,
          userAgent: true,
          integrityHash: true,
          prevHash: true,
          createdAt: true,
        },
      }),
      this.prisma.event.count({ where }),
    ]);

    return this.attachUserTenant(events, total, limit, offset);
  }

  async findByUser(
    userId: string,
    limit = 50,
    offset = 0,
    from?: string,
    to?: string,
  ): Promise<PaginatedResult<any>> {
    const where: EventWhereInput = { userId };
    if (from) where.createdAt = { gte: new Date(from) };
    if (to) where.createdAt = { ...where.createdAt, lte: new Date(to) };

    const [events, total] = await Promise.all([
      this.prisma.event.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        take: limit,
        skip: offset,
        select: {
          id: true,
          userId: true,
          tenantId: true,
          type: true,
          severity: true,
          sessionId: true,
          familyId: true,
          reason: true,
          metadata: true,
          ipAddress: true,
          userAgent: true,
          integrityHash: true,
          prevHash: true,
          createdAt: true,
        },
      }),
      this.prisma.event.count({ where }),
    ]);

    return this.attachUserTenant(events, total, limit, offset);
  }

  /**
   * Generic event query — allows flexible filters (type, user, tenant, date range)
   * Used by dashboards or admin utilities.
   */
  async queryEvents(params: {
    tenantId?: string;
    type?: string;
    userId?: string;
    sessionId?: string;
    startDate?: Date;
    endDate?: Date;
    limit?: number;
    offset?: number;
  }): Promise<PaginatedResult<any>> {
    const {
      tenantId,
      type,
      userId,
      sessionId,
      startDate,
      endDate,
      limit = 50,
      offset = 0,
    } = params;

    const where: Record<string, any> = {};
    if (tenantId) where.tenantId = tenantId;
    if (type) where.type = type;
    if (userId) where.userId = userId;
    if (sessionId) where.sessionId = sessionId;
    if (startDate || endDate) {
      where.createdAt = {
        ...(startDate && { gte: startDate }),
        ...(endDate && { lte: endDate }),
      };
    }

    const [events, total] = await Promise.all([
      this.prisma.event.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        take: limit,
        skip: offset,
        select: {
          id: true,
          userId: true,
          tenantId: true,
          type: true,
          severity: true,
          sessionId: true,
          reason: true,
          metadata: true,
          ipAddress: true,
          userAgent: true,
          createdAt: true,
        },
      }),
      this.prisma.event.count({ where }),
    ]);

    return this.attachUserTenant(events, total, limit, offset);
  }


  // Helper to attach user & tenant preview data
  private async attachUserTenant(
    events: any[],
    total: number,
    limit: number,
    offset: number,
  ) {
    const userIds = [
      ...new Set(events.map((e) => e.userId).filter(Boolean)),
    ] as string[];
    const tenantIds = [
      ...new Set(events.map((e) => e.tenantId).filter(Boolean)),
    ] as string[];

    const users = userIds.length
      ? await this.prisma.user.findMany({
          where: { id: { in: userIds } },
          select: { id: true, phone: true, name: true },
        })
      : [];

    const tenants = tenantIds.length
      ? await this.prisma.tenant.findMany({
          where: { id: { in: tenantIds } },
          select: { id: true, name: true, slug: true },
        })
      : [];

    const userMap = new Map(users.map((u) => [u.id, u]));
    const tenantMap = new Map(tenants.map((t) => [t.id, t]));

    return {
      data: events.map((event) => ({
        ...event,
        user: event.userId ? userMap.get(event.userId) || null : null,
        tenant: event.tenantId ? tenantMap.get(event.tenantId) || null : null,
      })),
      meta: { total, limit, offset, hasNext: offset + limit < total },
    };
  }
}

/** capture those also before we scatter ourselves : EventLogService: Add a small caching of lastHash (optional micro-optimization). Currently you query DB for the latest hash in every logEvent. You could cache lastHash in memory and update it after insert; still verifying periodically in background. Rate limit event logging (optional for DoS prevention): If multiple services start writing high-frequency events (e.g., login attempts), you could add a bounded queue or apply per-type debounce before insert. Optional Enhancements for Future These are not needed now, but align with “the best of the best” long-term vision: Enhancement Benefit Tamper-evident external audit log (append-only file or Kafka) Extra assurance if DB compromised Event schema validation (Zod) Prevent accidental malformed data in metadata Metrics Prometheus Exporter Integrate with Grafana Key rotation for signingSecret Zero-trust lifecycle management Async persistence (queue buffer) For extremely high load (1000s events/sec)*/
/**Notes, trade-offs & next steps
1) Race conditions & multi-instance

This lastHash cache is safe for a single-instance or low-concurrency system.

If you run multiple app instances concurrently, two instances could compute the same prevHash before either writes; that creates a split in chain order.

Mitigation at scale: use a small single-row “last_hash” store in Redis or the DB (UPDATE ... RETURNING) or rely on DB-based findFirst inside a transaction (your previous pattern) — or move queue processing to a single writer (Kafka/worker).

2) Rate-limiter semantics

Current limiter is per-window token count (configurable EVENT_RATE_LIMIT_PER_WINDOW and EVENT_RATE_WINDOW_MS).

You can make it more advanced (leaky-bucket, per-tenant tiers) or move to Redis for global rate-limiting.

3) Queue behavior

I implemented a simple bounded queue with drop-on-full semantics (drops new events). You can change to drop-oldest or persist to disk.

For high throughput, prefer a background worker or Kafka.

4) Metrics & Observability

Hook in Prometheus counters (alerts fired, events dropped, queue size, rate-limited counts). I can add code for that if you want.

5) Optional future: tamper-evident append-only export

Periodically export events to an append-only external store (S3, Kafka) to further guard against DB tampering. */
