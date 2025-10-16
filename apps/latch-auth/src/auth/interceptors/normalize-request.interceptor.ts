// src/auth/interceptors/normalize-request.interceptor.ts
import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { normalizeIp, normalizeUserAgent } from '../utils/normalize.util';
import type { RequestWithCookies } from '../types/auth.types'; // ✅ your existing type

@Injectable()
export class NormalizeRequestInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    // ✅ Cast to your typed request
    const req = context.switchToHttp().getRequest<RequestWithCookies>();

    req.normalizedIp = normalizeIp(req.ip);
    req.normalizedUserAgent = normalizeUserAgent(req.headers['user-agent']);

    return next.handle();
  }
}
