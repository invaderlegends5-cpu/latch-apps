import { EventLogService } from './event.service';
import * as authTypes from '../auth/types/auth.types';
export declare class TenantEventsController {
    private readonly eventLog;
    constructor(eventLog: EventLogService);
    recent(req: authTypes.AuthenticatedRequest, limit?: number, offset?: number): Promise<import("./event.service").PaginatedResult<any>>;
}
