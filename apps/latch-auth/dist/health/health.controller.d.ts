import { HttpStatus } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
export declare class HealthController {
    private readonly prisma;
    constructor(prisma: PrismaService);
    check(): Promise<{
        status: string;
        database: string;
        timestamp: string;
        statusCode?: undefined;
        error?: undefined;
        message?: undefined;
    } | {
        statusCode: HttpStatus;
        error: string;
        message: string;
        timestamp: string;
        status?: undefined;
        database?: undefined;
    }>;
}
