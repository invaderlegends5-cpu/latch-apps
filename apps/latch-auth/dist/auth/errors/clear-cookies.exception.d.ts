import { UnauthorizedException } from '@nestjs/common';
export declare class ClearCookiesUnauthorizedException extends UnauthorizedException {
    readonly clearCookies = true;
    constructor(message?: string | object);
}
