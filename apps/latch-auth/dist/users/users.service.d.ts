import { PrismaService } from '../prisma/prisma.service';
import { EventLogService } from '../events/event.service';
export declare class UsersService {
    private prisma;
    private eventLogService;
    constructor(prisma: PrismaService, eventLogService: EventLogService);
    findById(id: string): Promise<{
        tenantId: string;
        id: string;
        createdAt: Date;
        name: string | null;
        phone: string;
        email: string | null;
        passwordHash: string | null;
        isPhoneVerified: boolean;
        isEmailVerified: boolean;
        updatedAt: Date;
    } | null>;
    findByIdWithAccessCheck(requestingUserId: string, targetUserId: string, tenantId: string, ipAddress?: string | null, userAgent?: string | null): Promise<{
        tenantId: string;
        id: string;
        createdAt: Date;
        name: string | null;
        phone: string;
        email: string | null;
        passwordHash: string | null;
        isPhoneVerified: boolean;
        isEmailVerified: boolean;
        updatedAt: Date;
    } | null>;
    listForTenant(requestingUserId: string, tenantId: string, ipAddress?: string | null, userAgent?: string | null): Promise<{
        id: string;
        phone: string;
    }[]>;
    updateProfile(userId: string, tenantId: string, updates: {
        phone?: string;
    }, ipAddress?: string | null, userAgent?: string | null): Promise<{
        tenantId: string;
        id: string;
        createdAt: Date;
        name: string | null;
        phone: string;
        email: string | null;
        passwordHash: string | null;
        isPhoneVerified: boolean;
        isEmailVerified: boolean;
        updatedAt: Date;
    }>;
}
