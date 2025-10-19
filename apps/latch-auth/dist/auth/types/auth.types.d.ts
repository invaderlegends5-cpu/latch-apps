import { Session, RefreshToken, User, Tenant } from '@prisma/client';
import express from 'express';
export interface TokenPayload {
    sub: string;
    tenantId: string;
    mfa: boolean;
    sessionId: string;
}
export interface AuthResponse {
    ok: boolean;
    accessToken: string;
    refreshToken: string;
    sessionId: string;
    user: {
        id: string;
        phone: string;
        tenantId: string;
    };
}
export interface RefreshTokenResult {
    session: Session;
    refreshTokenPlain: string;
    refreshTokenRecord: RefreshToken;
}
export interface SessionWithUser extends Session {
    user: User;
    tenant?: Tenant;
}
export interface AuthenticatedRequest extends express.Request {
    user: {
        id: string;
        email?: string;
        tenantId?: string;
    };
    tenant?: Tenant;
}
export interface RequestWithCookies extends express.Request {
    cookies: {
        latch_refresh?: string;
        latch_session?: string;
    };
    normalizedIp?: string | null;
    normalizedUserAgent?: string | null;
}
export interface PrismaError {
    code: string;
    meta?: any;
    message: string;
}
