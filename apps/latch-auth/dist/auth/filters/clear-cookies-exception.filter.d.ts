import { ExceptionFilter, ArgumentsHost } from '@nestjs/common';
import { ClearCookiesUnauthorizedException } from '../exceptions/clear-cookies-unauthorized.exception';
export declare class ClearCookiesExceptionFilter implements ExceptionFilter {
    catch(exception: ClearCookiesUnauthorizedException, host: ArgumentsHost): void;
}
