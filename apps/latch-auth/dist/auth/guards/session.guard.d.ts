import { CanActivate, ExecutionContext } from '@nestjs/common';
import { AuthService } from '../auth.service';
import { EventLogService } from '../../events/event.service';
export declare class SessionGuard implements CanActivate {
    private readonly authService;
    private readonly eventLogService;
    constructor(authService: AuthService, eventLogService: EventLogService);
    canActivate(context: ExecutionContext): Promise<boolean>;
}
