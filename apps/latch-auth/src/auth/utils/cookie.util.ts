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
  // Updated to handle Docker/test environments properly
  secure: process.env.NODE_ENV === 'production' && 
          process.env.DOCKER_ENV !== 'test' && 
          process.env.DOCKER_ENV !== 'development',
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
  
  // Determine if we're in a Docker/test environment
  const isProd = process.env.NODE_ENV === 'production';
  const isDockerTest = process.env.DOCKER_ENV === 'test' || process.env.DOCKER_ENV === 'development';
  const isSecure = isProd && !isDockerTest;
  
  // Refresh token
  res.cookie(REFRESH_COOKIE_NAME, refreshToken, {
    ...baseOptions,
    httpOnly: true,
    maxAge,
    secure: isSecure,
    signed: false,
    domain: isProd && !isDockerTest ? process.env.COOKIE_DOMAIN : undefined,
  });

  // Session ID
  res.cookie(SESSION_COOKIE_NAME, sessionId, {
    ...baseOptions,
    httpOnly: true,
    maxAge,
    secure: isSecure,
  });

  // CSRF token (readable by JS)
  if (csrfToken) {
    res.cookie(CSRF_COOKIE_NAME, csrfToken, {
      ...baseOptions,
      httpOnly: false, // CSRF token needs to be accessible by JS
      maxAge,
      secure: isSecure,
    });
  }
}

export function clearRefreshCookies(res: Response) {
  const isProd = process.env.NODE_ENV === 'production';
  const isDockerTest = process.env.DOCKER_ENV === 'test' || process.env.DOCKER_ENV === 'development';
  const isSecure = isProd && !isDockerTest;
  
  const expired = { 
    ...baseOptions, 
    expires: new Date(0),
    secure: isSecure,
  };

  res.cookie(REFRESH_COOKIE_NAME, '', { ...expired, httpOnly: true });
  res.cookie(SESSION_COOKIE_NAME, '', { ...expired, httpOnly: true });
  res.cookie(CSRF_COOKIE_NAME, '', { ...expired, httpOnly: false });
}
