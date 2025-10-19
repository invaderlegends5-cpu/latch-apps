import { PrismaService } from '../prisma/prisma.service';
import { EventLogService } from '../events/event.service';
export declare class SessionCleanerService {
    private readonly prisma;
    private readonly eventLogService;
    private readonly logger;
    constructor(prisma: PrismaService, eventLogService: EventLogService);
    pruneExpiredSessions(): Promise<void>;
}
