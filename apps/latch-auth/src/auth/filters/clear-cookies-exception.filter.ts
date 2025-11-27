// src/auth/filters/clear-cookies-exception.filter.ts
import { ExceptionFilter, Catch, ArgumentsHost } from '@nestjs/common';
import { Response } from 'express';
import { ClearCookiesUnauthorizedException } from '../exceptions/clear-cookies-unauthorized.exception';
import { clearRefreshCookies } from '../utils/cookie.util';

@Catch(ClearCookiesUnauthorizedException)
export class ClearCookiesExceptionFilter implements ExceptionFilter {
  catch(exception: ClearCookiesUnauthorizedException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const res = ctx.getResponse<Response>();

    // 🔥 Always clear cookies on this exception
    clearRefreshCookies(res);

    res.status(exception.getStatus()).json({
      statusCode: exception.getStatus(),
      message: exception.message,
      clearCookies: true, // 👈 optional flag for frontend
    });
  }
}
