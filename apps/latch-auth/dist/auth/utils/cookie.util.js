"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CSRF_COOKIE_NAME = exports.SESSION_COOKIE_NAME = exports.REFRESH_COOKIE_NAME = void 0;
exports.setRefreshCookies = setRefreshCookies;
exports.clearRefreshCookies = clearRefreshCookies;
exports.REFRESH_COOKIE_NAME = 'latch_refresh';
exports.SESSION_COOKIE_NAME = 'latch_session';
exports.CSRF_COOKIE_NAME = 'latch_csrf';
const baseOptions = {
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    signed: false,
    path: '/',
};
function setRefreshCookies(res, refreshToken, sessionId, csrfToken, opts) {
    const maxAge = (opts?.maxAgeDays ?? 7) * 24 * 60 * 60 * 1000;
    const isProd = process.env.NODE_ENV === 'production';
    res.cookie(exports.REFRESH_COOKIE_NAME, refreshToken, {
        ...baseOptions,
        httpOnly: true,
        maxAge,
        secure: isProd,
        signed: false,
        domain: isProd ? process.env.COOKIE_DOMAIN : undefined,
    });
    res.cookie(exports.SESSION_COOKIE_NAME, sessionId, {
        ...baseOptions,
        httpOnly: true,
        maxAge,
    });
    if (csrfToken) {
        res.cookie(exports.CSRF_COOKIE_NAME, csrfToken, {
            ...baseOptions,
            httpOnly: false,
            maxAge,
        });
    }
}
function clearRefreshCookies(res) {
    const expired = { ...baseOptions, expires: new Date(0) };
    res.cookie(exports.REFRESH_COOKIE_NAME, '', { ...expired, httpOnly: true });
    res.cookie(exports.SESSION_COOKIE_NAME, '', { ...expired, httpOnly: true });
    res.cookie(exports.CSRF_COOKIE_NAME, '', { ...expired, httpOnly: false });
}
//# sourceMappingURL=cookie.util.js.map