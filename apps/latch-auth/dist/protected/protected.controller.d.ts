import type { Response } from 'express';
import type { AuthenticatedRequest } from '../auth/types/auth.types';
import { EventLogService } from '../events/event.service';
export declare class ProtectedController {
    private eventLogService;
    constructor(eventLogService: EventLogService);
    me(req: AuthenticatedRequest, res: Response): Promise<{
        ok: boolean;
        user: {
            id: string;
            email?: string;
            tenantId?: string;
        };
        tenant: {
            id: string;
            createdAt: Date;
            name: string;
            updatedAt: Date;
            slug: string;
            branding: import("@prisma/client/runtime/library").JsonValue | null;
        } | undefined;
    }>;
    getAuditTrail(req: AuthenticatedRequest): Promise<void>;
    exportUserData(req: AuthenticatedRequest): Promise<void>;
    getSecurityStatus(req: AuthenticatedRequest): Promise<{
        ok: boolean;
        securityStatus: {
            authentication: string;
            authorization: string;
            sessionManagement: string;
            lastSecurityCheck: Date;
        };
    }>;
    verifyAuthentication(req: AuthenticatedRequest): Promise<{
        ok: boolean;
        message: string;
        user: {
            id: string;
            email?: string;
            tenantId?: string;
        };
    }>;
}
