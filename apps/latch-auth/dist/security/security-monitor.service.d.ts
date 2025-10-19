import { OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { EventLogService } from '../events/event.service';
export declare class SecurityMonitoringService implements OnModuleInit, OnModuleDestroy {
    private readonly events;
    private readonly config;
    private readonly logger;
    private webhookUrl?;
    private windowMinutes;
    private thresholds;
    private eventBuckets;
    private cleanupInterval;
    constructor(events: EventLogService, config: ConfigService);
    onModuleInit(): void;
    onModuleDestroy(): void;
    private handleEvent;
    private getAggregationKey;
    private evaluateThreshold;
    private pruneOldEntries;
    private limitBuckets;
    private postWithRetry;
    private triggerAlert;
    getSecurityStatus(): Record<string, number>;
}
