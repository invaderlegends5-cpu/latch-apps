import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';
import { SecurityEvent, EventType, EventSeverity, EventMeta, ChainVerificationValid, ChainVerificationBroken } from './event.types';
export interface PaginatedResult<T> {
    data: T[];
    meta: {
        total: number;
        limit: number;
        offset: number;
        hasNext: boolean;
    };
}
export declare class EventLogService {
    private readonly prisma;
    private readonly config;
    private readonly logger;
    private readonly eventSubject;
    readonly event$: import("rxjs").Observable<SecurityEvent>;
    private readonly signingSecret;
    constructor(prisma: PrismaService, config: ConfigService);
    private maskIp;
    private truncateUserAgent;
    private computeIntegrity;
    private sortObjectKeys;
    logEvent(type: EventType, opts?: {
        userId?: string | null;
        tenantId?: string | null;
        metadata?: EventMeta;
        ipAddress?: string | null;
        userAgent?: string | null;
        severity?: EventSeverity;
    }): Promise<{
        sessionId: string | null;
        familyId: string | null;
        reason: string | null;
        userId: string | null;
        tenantId: string | null;
        metadata: import("@prisma/client/runtime/library").JsonValue | null;
        ipAddress: string | null;
        userAgent: string | null;
        severity: import("@prisma/client").$Enums.EventSeverity;
        id: string;
        type: import("@prisma/client").$Enums.EventType;
        integrityHash: string;
        prevHash: string | null;
        createdAt: Date;
    } | null>;
    verifyChain(): Promise<ChainVerificationValid | ChainVerificationBroken>;
    findRecent(limit?: number, offset?: number, from?: string, to?: string): Promise<PaginatedResult<any>>;
    findByType(type: EventType, limit?: number, offset?: number, from?: string, to?: string): Promise<PaginatedResult<any>>;
    findByUser(userId: string, limit?: number, offset?: number, from?: string, to?: string): Promise<PaginatedResult<any>>;
    queryEvents(params: {
        tenantId?: string;
        type?: string;
        userId?: string;
        sessionId?: string;
        startDate?: Date;
        endDate?: Date;
        limit?: number;
        offset?: number;
    }): Promise<PaginatedResult<any>>;
    private attachUserTenant;
}
