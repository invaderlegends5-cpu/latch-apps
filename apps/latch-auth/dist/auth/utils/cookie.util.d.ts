import { Response } from 'express';
export declare const REFRESH_COOKIE_NAME = "latch_refresh";
export declare const SESSION_COOKIE_NAME = "latch_session";
export declare const CSRF_COOKIE_NAME = "latch_csrf";
export declare function setRefreshCookies(res: Response, refreshToken: string, sessionId: string, csrfToken?: string, opts?: {
    maxAgeDays?: number;
}): void;
export declare function clearRefreshCookies(res: Response): void;
