import express from 'express';
import { AuthService } from './auth.service';
import { RequestOtpDto } from './dto/request-otp.dto';
import { VerifyOtpDto } from './dto/verify-otp.dto';
import * as authTypes from './types/auth.types';
import { EventLogService } from '../events/event.service';
export declare class AuthController {
    private auth;
    private eventLogService;
    constructor(auth: AuthService, eventLogService: EventLogService);
    requestOtp(dto: RequestOtpDto, req: express.Request): Promise<{
        ok: boolean;
        message: string;
    }>;
    verifyOtp(dto: VerifyOtpDto, req: express.Request, res: express.Response): Promise<{
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
    refresh(req: authTypes.RequestWithCookies, res: express.Response): Promise<{
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
    logout(req: authTypes.RequestWithCookies, res: express.Response): Promise<{
        ok: boolean;
    }>;
    revokeAll(req: authTypes.AuthenticatedRequest, res: express.Response): Promise<{
        ok: boolean;
        revokedCount: number;
    }>;
}
