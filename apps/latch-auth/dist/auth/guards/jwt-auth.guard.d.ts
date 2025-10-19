import { ExecutionContext } from '@nestjs/common';
import { EventLogService } from '../../events/event.service';
declare const JwtAuthGuard_base: import("@nestjs/passport").Type<import("@nestjs/passport").IAuthGuard>;
export declare class JwtAuthGuard extends JwtAuthGuard_base {
    private eventLogService;
    constructor(eventLogService: EventLogService);
    canActivate(context: ExecutionContext): Promise<boolean>;
    private logAuthFailure;
}
export {};
