// src/auth/utils/cookie.util.ts
import { Response } from 'express';

export const REFRESH_COOKIE_NAME = 'latch_refresh';
export const SESSION_COOKIE_NAME = 'latch_session';
export const CSRF_COOKIE_NAME = 'latch_csrf';

/**
 * Cookie options:
 * - sameSite: 'lax' → safer against CSRF than 'none', but still allows
 *   cookies on top-level redirects (needed for external login flows, e.g. tenant OAuth).
 *   Do NOT change to 'strict' unless you are 100% sure you don't rely on redirects.
 * - secure: true in production → prevents MITM on HTTP.
 * - path: '/' → ensures clear() matches set().
 */
const baseOptions = {
  sameSite: 'lax' as const,
  secure: process.env.NODE_ENV === 'production',
  signed: false,
  path: '/', // ✅ added so set & clear match
};

export function setRefreshCookies(
  res: Response,
  refreshToken: string,
  sessionId: string,
  csrfToken?: string,
  opts?: { maxAgeDays?: number },
) {
  const maxAge = (opts?.maxAgeDays ?? 7) * 24 * 60 * 60 * 1000;
  const isProd = process.env.NODE_ENV === 'production';
  // Refresh token
  res.cookie(REFRESH_COOKIE_NAME, refreshToken, {
    ...baseOptions,
    httpOnly: true,
    maxAge,
    secure: isProd,
    signed: false,
    domain: isProd ? process.env.COOKIE_DOMAIN : undefined,
  });

  // Session ID
  res.cookie(SESSION_COOKIE_NAME, sessionId, {
    ...baseOptions,
    httpOnly: true,
    maxAge,
  });

  // CSRF token (readable by JS)
  if (csrfToken) {
    res.cookie(CSRF_COOKIE_NAME, csrfToken, {
      ...baseOptions,
      httpOnly: false,
      maxAge,
    });
  }
}

export function clearRefreshCookies(res: Response) {
  const expired = { ...baseOptions, expires: new Date(0) };

  res.cookie(REFRESH_COOKIE_NAME, '', { ...expired, httpOnly: true });
  res.cookie(SESSION_COOKIE_NAME, '', { ...expired, httpOnly: true });
  res.cookie(CSRF_COOKIE_NAME, '', { ...expired, httpOnly: false });
}
