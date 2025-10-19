import { CanActivate, ExecutionContext } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { EventLogService } from '../../events/event.service';
export declare class CsrfGuard implements CanActivate {
    private prisma;
    private eventLogService;
    constructor(prisma: PrismaService, eventLogService: EventLogService);
    canActivate(context: ExecutionContext): Promise<boolean>;
}
