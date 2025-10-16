// src/events/tenant-events.controller.ts
import {
  Controller,
  Get,
  Query,
  UseGuards,
  BadRequestException,
  Req,
} from '@nestjs/common';
import { EventLogService } from './event.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { TenantGuard } from '../auth/guards/tenant.guard';
import * as authTypes from 'src/auth/types/auth.types';
import { SessionGuard } from 'src/auth/guards/session.guard';

@Controller('tenant/events')
@UseGuards(JwtAuthGuard, SessionGuard, TenantGuard) // ✅ tenant isolation guaranteed
export class TenantEventsController {
  constructor(private readonly eventLog: EventLogService) {}

  // Example: get recent events for this tenant
  @Get('recent')
  async recent(
    @Req() req: authTypes.AuthenticatedRequest,
    @Query('limit') limit = 50,
    @Query('offset') offset = 0,
  ) {
    const parsedLimit = Number(limit);
    const parsedOffset = Number(offset);

    if (isNaN(parsedLimit) || parsedLimit < 1 || parsedLimit > 1000) {
      throw new BadRequestException('Limit must be between 1 and 1000');
    }
    if (isNaN(parsedOffset) || parsedOffset < 0) {
      throw new BadRequestException('Offset must be >= 0');
    }

    // 🔒 TenantGuard will already set tenantId on request.user
    const tenantId = req.user.tenantId;

    return this.eventLog.findRecent(
      parsedLimit,
      parsedOffset,
      tenantId,
      undefined,
    );
    // TODO: extend findRecent to accept tenantId filter
  }
}
