// src/auth/exceptions/clear-cookies-unauthorized.exception.ts
import { UnauthorizedException } from '@nestjs/common';

export class ClearCookiesUnauthorizedException extends UnauthorizedException {
  constructor(message = 'Unauthorized - clear cookies') {
    super(message);
  }
}
