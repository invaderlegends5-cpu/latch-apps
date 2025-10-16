// src/auth/errors/clear-cookies.exception.ts
import { UnauthorizedException } from '@nestjs/common';

/**
 * Special UnauthorizedException that signals controllers to clear auth cookies.
 * Controllers should catch this exception, call clearRefreshCookies(res), then rethrow/handle.
 */
export class ClearCookiesUnauthorizedException extends UnauthorizedException {
  public readonly clearCookies = true;

  constructor(message?: string | object) {
    super(message);
  }
}
