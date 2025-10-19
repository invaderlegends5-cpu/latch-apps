import { UnauthorizedException } from '@nestjs/common';
export declare class ClearCookiesUnauthorizedException extends UnauthorizedException {
    constructor(message?: string);
}
