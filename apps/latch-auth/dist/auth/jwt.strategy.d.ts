import { PrismaService } from '../prisma/prisma.service';
import { EventLogService } from '../events/event.service';
declare const JwtStrategy_base: new (...args: any) => any;
export declare class JwtStrategy extends JwtStrategy_base {
    private prisma;
    private eventLogService;
    constructor(prisma: PrismaService, eventLogService: EventLogService);
    validate(payload: any): Promise<{
        sub: any;
        tenantId: any;
        sessionId: any;
        mfa: any;
    }>;
}
export {};
