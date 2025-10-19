import { PrismaService } from '../prisma/prisma.service';
import { RequestOtpDto } from './dto/request-otp.dto';
import { VerifyOtpDto } from './dto/verify-otp.dto';
import { JwtService } from '@nestjs/jwt';
import { EventLogService } from '../events/event.service';
type RequestContext = {
    ipAddress?: string | null;
    userAgent?: string | null;
};
export declare class AuthService {
    private prisma;
    private jwtService;
    private eventLogService;
    constructor(prisma: PrismaService, jwtService: JwtService, eventLogService: EventLogService);
    requestOtp(dto: RequestOtpDto, requestContext?: RequestContext): Promise<{
        ok: boolean;
        message: string;
    }>;
    verifyOtp(dto: VerifyOtpDto, requestContext?: RequestContext): Promise<{
        ok: boolean;
        accessToken: string;
        refreshToken: string;
        sessionId: string;
        csrfToken: string;
        user: {
            id: string;
            phone: string;
            tenantId: string;
        };
    }>;
    getUserBySessionId(sessionId: string, requestContext?: RequestContext): Promise<{
        id: string;
        tenantId: string;
    } | null>;
    refreshTokens(refreshToken: string, sessionId: string, requestContext?: RequestContext): Promise<{
        ok: boolean;
        accessToken: string;
        refreshToken: string;
        sessionId: string;
        csrfToken: string;
        familyId: string;
        user: {
            id: string;
            phone: string;
            tenantId: string;
        };
    }>;
    private handleTokenReuse;
    getActiveSessionCount(userId: string): Promise<number>;
    revokeSession(sessionId: string, requestContext?: RequestContext): Promise<{
        ok: boolean;
    }>;
    revokeAllSessionsForUser(userId: string, requestContext?: RequestContext): Promise<number>;
}
export {};
