import { CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { PrismaService } from '../../prisma/prisma.service';
import { EventLogService } from '../../events/event.service';
export declare class RolesGuard implements CanActivate {
    private readonly reflector;
    private readonly prisma;
    private readonly eventLog;
    private readonly logger;
    constructor(reflector: Reflector, prisma: PrismaService, eventLog: EventLogService);
    canActivate(context: ExecutionContext): Promise<boolean>;
    private logDenied;
}
