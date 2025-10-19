import { SecurityMonitoringService } from './security-monitor.service';
import { EventLogService } from '../events/event.service';
export declare class SecurityController {
    private readonly monitor;
    private readonly eventLog;
    private readonly logger;
    constructor(monitor: SecurityMonitoringService, eventLog: EventLogService);
    getSecurityStatus(): Promise<{
        ok: boolean;
        timestamp: string;
        threatSummary: Record<string, number> | {
            info: string;
        };
        chain: {
            valid: false;
            total: null;
            brokenIndex: null;
            error: string;
        } | {
            valid: false;
            total: number;
            brokenIndex: number;
            error: null;
        } | {
            valid: true;
            total: number;
            brokenIndex: null;
            error: null;
        };
        recentCounts: Record<string, number | null>;
        error?: undefined;
    } | {
        ok: boolean;
        error: string;
        timestamp?: undefined;
        threatSummary?: undefined;
        chain?: undefined;
        recentCounts?: undefined;
    }>;
}
