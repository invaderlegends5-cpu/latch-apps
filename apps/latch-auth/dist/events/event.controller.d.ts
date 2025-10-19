import { EventLogService, PaginatedResult } from './event.service';
export declare class EventController {
    private readonly eventLog;
    constructor(eventLog: EventLogService);
    recent(res: Response, limit?: number, offset?: number, from?: string, to?: string): Promise<PaginatedResult<any>>;
    byType(res: Response, type: string, limit?: number, offset?: number, from?: string, to?: string): Promise<PaginatedResult<any>>;
    byUser(res: Response, userId: string, limit?: number, offset?: number, from?: string, to?: string): Promise<PaginatedResult<any>>;
}
