// // src/events/event.controller.ts
// import {
//   Controller,
//   Get,
//   Query,
//   UseGuards,
//   BadRequestException,
// } from '@nestjs/common';
// import { EventLogService } from './event.service';
// import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
// import { TenantGuard } from '../auth/guards/tenant.guard';
// import { $Enums } from '@prisma/client';

// @Controller('admin/events')
// @UseGuards(JwtAuthGuard, TenantGuard) // 🔐 Only authenticated + correct tenant
// export class EventController {
//   constructor(private readonly eventLog: EventLogService) {}

//   @Get('recent')
//   async recent(@Query('limit') limit = 50, @Query('offset') offset = 0) {
//     const parsedLimit = Number(limit);
//     const parsedOffset = Number(offset);
//     if (isNaN(parsedLimit) || parsedLimit < 1 || parsedLimit > 1000) {
//       throw new BadRequestException(
//         'Limit must be a number between 1 and 1000',
//       );
//     }
//     if (isNaN(parsedOffset) || parsedOffset < 0) {
//       throw new BadRequestException('Offset must be a non-negative number');
//     }
//     return this.eventLog.findRecent(parsedLimit, parsedOffset);
//   }

//   @Get('type')
//   async byType(
//     @Query('type') type: string,
//     @Query('limit') limit = 50,
//     @Query('offset') offset = 0,
//   ) {
//     const parsedLimit = Number(limit);
//     const parsedOffset = Number(offset);
//     if (isNaN(parsedLimit) || parsedLimit < 1 || parsedLimit > 1000) {
//       throw new BadRequestException(
//         'Limit must be a number between 1 and 1000',
//       );
//     }

//     if (!type) {
//       throw new BadRequestException('Event type is required');
//     }

//     // ✅ Type-safe validation using type guard
//     const isValidType = (value: string): value is $Enums.EventType => {
//       return Object.values($Enums.EventType).includes(
//         value as $Enums.EventType,
//       );
//     };

//     if (!isValidType(type)) {
//       throw new BadRequestException(`Invalid event type: ${type}`);
//     }

//     return this.eventLog.findByType(type, parsedLimit, parsedOffset);
//   }

//   @Get('user')
//   async byUser(
//     @Query('userId') userId: string,
//     @Query('limit') limit = 50,
//     @Query('offset') offset = 0,
//   ) {
//     const parsedLimit = Number(limit);
//     const parsedOffset = Number(offset);
//     if (isNaN(parsedLimit) || parsedLimit < 1 || parsedLimit > 1000) {
//       throw new BadRequestException(
//         'Limit must be a number between 1 and 1000',
//       );
//     }

//     if (!userId) {
//       throw new BadRequestException('User ID is required');
//     }

//     return this.eventLog.findByUser(userId, parsedLimit, parsedOffset);
//   }
// }

// src/events/event.controller.ts
import {
  Controller,
  Get,
  Query,
  UseGuards,
  BadRequestException,
  Response,
  Res,
  UseInterceptors,
} from '@nestjs/common';
import { CacheControlInterceptor } from '../interceptors/cache-control.interceptor';
import { EventLogService, PaginatedResult } from './event.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { TenantGuard } from '../auth/guards/tenant.guard';
import { $Enums } from '@prisma/client';
import { SessionGuard } from '../auth/guards/session.guard';

@Controller('admin/events')
@UseGuards(JwtAuthGuard, SessionGuard, TenantGuard) // 🔐 Only authenticated + correct tenant
@UseInterceptors(CacheControlInterceptor)
export class EventController {
  constructor(private readonly eventLog: EventLogService) {}

  @Get('recent')
  async recent(
    @Res({ passthrough: true }) res: Response,
    @Query('limit') limit = 50,
    @Query('offset') offset = 0,
    @Query('from') from?: string,
    @Query('to') to?: string,
  ): Promise<PaginatedResult<any>> {
    const parsedLimit = Number(limit);
    const parsedOffset = Number(offset);

    if (isNaN(parsedLimit) || parsedLimit < 1 || parsedLimit > 1000) {
      throw new BadRequestException(
        'Limit must be a number between 1 and 1000',
      );
    }

    if (isNaN(parsedOffset) || parsedOffset < 0) {
      throw new BadRequestException('Offset must be a non-negative number');
    }

    // Validate date strings
    let parsedFrom: Date | undefined;
    let parsedTo: Date | undefined;

    if (from) {
      parsedFrom = new Date(from);
      if (isNaN(parsedFrom.getTime())) {
        throw new BadRequestException('Invalid from date format');
      }
    }

    if (to) {
      parsedTo = new Date(to);
      if (isNaN(parsedTo.getTime())) {
        throw new BadRequestException('Invalid to date format');
      }
    }

    // Remove cache control headers - will add via interceptor
    return this.eventLog.findRecent(
      parsedLimit,
      parsedOffset,
      parsedFrom?.toISOString(),
      parsedTo?.toISOString(),
    );
  }

  @Get('type')
  async byType(
    @Res({ passthrough: true }) res: Response, // ✅ Move required parameter to beginning
    @Query('type') type: string,
    @Query('limit') limit = 50,
    @Query('offset') offset = 0,
    @Query('from') from?: string,
    @Query('to') to?: string,
  ) {
    const parsedLimit = Number(limit);
    const parsedOffset = Number(offset);

    if (isNaN(parsedLimit) || parsedLimit < 1 || parsedLimit > 1000) {
      throw new BadRequestException(
        'Limit must be a number between 1 and 1000',
      );
    }

    if (isNaN(parsedOffset) || parsedOffset < 0) {
      throw new BadRequestException('Offset must be a non-negative number');
    }

    if (!type) {
      throw new BadRequestException('Event type is required');
    }

    // Validate against Prisma's generated enum
    const isValidType = (value: string): value is $Enums.EventType => {
      return Object.values($Enums.EventType).includes(
        value as $Enums.EventType,
      );
    };

    if (!isValidType(type)) {
      throw new BadRequestException(`Invalid event type: ${type}`);
    }

    // Validate date strings
    let parsedFrom: Date | undefined;
    let parsedTo: Date | undefined;

    if (from) {
      parsedFrom = new Date(from);
      if (isNaN(parsedFrom.getTime())) {
        throw new BadRequestException('Invalid from date format');
      }
    }

    if (to) {
      parsedTo = new Date(to);
      if (isNaN(parsedTo.getTime())) {
        throw new BadRequestException('Invalid to date format');
      }
    }

    // Remove cache control headers - will add via interceptor
    return this.eventLog.findByType(
      type,
      parsedLimit,
      parsedOffset,
      parsedFrom?.toISOString(),
      parsedTo?.toISOString(),
    );
  }

  @Get('user')
  async byUser(
    @Res({ passthrough: true }) res: Response, // ✅ Move required parameter to beginning
    @Query('userId') userId: string,
    @Query('limit') limit = 50,
    @Query('offset') offset = 0,
    @Query('from') from?: string,
    @Query('to') to?: string,
  ) {
    const parsedLimit = Number(limit);
    const parsedOffset = Number(offset);

    if (isNaN(parsedLimit) || parsedLimit < 1 || parsedLimit > 1000) {
      throw new BadRequestException(
        'Limit must be a number between 1 and 1000',
      );
    }

    if (isNaN(parsedOffset) || parsedOffset < 0) {
      throw new BadRequestException('Offset must be a non-negative number');
    }

    if (!userId) {
      throw new BadRequestException('User ID is required');
    }

    // Validate date strings
    let parsedFrom: Date | undefined;
    let parsedTo: Date | undefined;

    if (from) {
      parsedFrom = new Date(from);
      if (isNaN(parsedFrom.getTime())) {
        throw new BadRequestException('Invalid from date format');
      }
    }

    if (to) {
      parsedTo = new Date(to);
      if (isNaN(parsedTo.getTime())) {
        throw new BadRequestException('Invalid to date format');
      }
    }

    // Remove cache control headers - will add via interceptor
    return this.eventLog.findByUser(
      userId,
      parsedLimit,
      parsedOffset,
      parsedFrom?.toISOString(),
      parsedTo?.toISOString(),
    );
  }
}
