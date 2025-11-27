// src/events/tenant-events.controller.ts
import {
  Controller,
  Get,
  Query,
  UseGuards,
  BadRequestException,
  Req,
  Logger,
  DefaultValuePipe,
  ParseIntPipe,
  UseInterceptors,
  ClassSerializerInterceptor,
  ForbiddenException,
} from '@nestjs/common';
import { EventLogService, PaginatedResult } from './event.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { TenantGuard } from '../auth/guards/tenant.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import * as authTypes from '../auth/types/auth.types';
import { SessionGuard } from '../auth/guards/session.guard';
import { CacheControlInterceptor } from '../interceptors/cache-control.interceptor';
import { 
  ApiTags, 
  ApiOperation, 
  ApiResponse, 
  ApiQuery, 
  ApiBearerAuth,
  ApiSecurity,
} from '@nestjs/swagger';
import { IPReputationService } from '@/ip-reputation/ip-reputation.service';

// Response DTOs
class EventResponseDto {
  id: string;
  type: string;
  severity: string;
  userId: string | null;
  tenantId: string;
  metadata: any;
  ipAddress: string | null;
  userAgent: string | null;
  integrityHash: string;
  prevHash: string | null;
  createdAt: Date;
  user?: {
    id: string;
    name: string;
    phone: string;
  } | null;
  tenant?: {
    id: string;
    name: string;
    slug: string;
  } | null;
}

class PaginatedEventsResponseDto {
   EventResponseDto: any[];
  meta: {
    total: number;
    limit: number;
    offset: number;
    hasNext: boolean;
  };
}

class EventCountsDto {
  total: number;
  security: number;
  info: number;
  error: number;
}

@ApiTags('tenant-events')
@Controller('tenant/events')
@ApiBearerAuth()
@ApiSecurity('csrf-token')
@UseInterceptors(ClassSerializerInterceptor)
@UseGuards(JwtAuthGuard, SessionGuard, TenantGuard) 
export class TenantEventsController {
  private readonly logger = new Logger(TenantEventsController.name);

  constructor(
    private readonly eventLog: EventLogService,
    private readonly ipReputationService: IPReputationService, 
  ) {}

  @Get('recent')
  @ApiOperation({ 
    summary: 'Get recent events for current tenant', 
    description: 'Returns recent audit events for the current tenant with pagination support.'
  })
  @ApiQuery({ name: 'limit', required: false, type: Number, description: 'Number of events to return (1-1000)', example: 50 })
  @ApiQuery({ name: 'offset', required: false, type: Number, description: 'Offset for pagination', example: 0 })
  @ApiQuery({ name: 'type', required: false, type: String, description: 'Filter by event type', example: 'LOGIN' })
  @ApiQuery({ name: 'severity', required: false, type: String, description: 'Filter by severity level', example: 'INFO' })
  @ApiQuery({ name: 'userId', required: false, type: String, description: 'Filter by specific user ID', example: 'user-123' })
  @ApiQuery({ name: 'startDate', required: false, type: String, description: 'Filter events from this date (ISO format)', example: '2023-01-01T00:00:00Z' })
  @ApiQuery({ name: 'endDate', required: false, type: String, description: 'Filter events until this date (ISO format)', example: '2023-12-31T23:59:59Z' })
  @ApiResponse({ 
    status: 200, 
    description: 'Successfully retrieved tenant events', 
    type: PaginatedEventsResponseDto 
  })
  @ApiResponse({ status: 400, description: 'Invalid parameters' })
  @ApiResponse({ status: 403, description: 'Insufficient permissions' })
  @UseInterceptors(CacheControlInterceptor)
  async recent(
    @Req() req: authTypes.AuthenticatedRequest,
    @Query('limit', new DefaultValuePipe('50'), ParseIntPipe) limit: number,
    @Query('offset', new DefaultValuePipe('0'), ParseIntPipe) offset: number,
    @Query('type') type?: string,
    @Query('severity') severity?: string,
    @Query('userId') userId?: string,
    @Query('startDate') startDate?: string,
    @Query('endDate') endDate?: string,
  ) {
    const ipAddress = req.ip || req.socket.remoteAddress || 'unknown';
    if (ipAddress && ipAddress !== 'unknown' && await this.ipReputationService.isIPBlocked(ipAddress)) {
      await this.eventLog.logEvent('SECURITY_CSRF_ERROR', {
        userId: req.user.id,
        tenantId: req.tenant?.id,
        metadata: { 
          reason: 'BLOCKED_IP_AUDIT_ACCESS_ATTEMPT',
          endpoint: '/tenant/events/recent',
          action: 'GET_TENANT_EVENTS',
        },
        ipAddress: ipAddress,
        userAgent: req.headers['user-agent'] as string,
        severity: 'CRITICAL',
      });
      
      throw new ForbiddenException('Audit trail access denied - IP address is blocked');
    }

    // Validate parameters
    if (limit < 1 || limit > 1000) {
      throw new BadRequestException('Limit must be between 1 and 1000');
    }
    if (offset < 0) {
      throw new BadRequestException('Offset must be >= 0');
    }

    // Validate date parameters if provided
    if (startDate && isNaN(Date.parse(startDate))) {
      throw new BadRequestException('startDate must be a valid ISO date string');
    }
    if (endDate && isNaN(Date.parse(endDate))) {
      throw new BadRequestException('endDate must be a valid ISO date string');
    }

    // Parse dates
    const start = startDate ? new Date(startDate) : undefined;
    const end = endDate ? new Date(endDate) : undefined;

    // 🔒 TenantGuard ensures tenant isolation - tenantId comes from tenant guard
    const tenantId = req.tenant?.id; // Use req.tenant.id from TenantGuard
    
    if (!tenantId) {
      throw new BadRequestException('Tenant context not available');
    }
    const userIdFromToken = req.user.id;
    // Log the access attempt
    await this.eventLog.logEvent('AUDIT_TRAIL_ACCESSED', {
      userId: req.user.id,
      tenantId: tenantId,
      metadata: {
        action: 'GET_TENANT_EVENTS',
        limit,
        offset,
        filters: {
          type,
          severity,
          userId,
          startDate,
          endDate,
        },
      },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'] as string,
      severity: 'INFO',
    });

    try {
      const result: PaginatedResult<any> = await this.eventLog.queryEvents({
        tenantId,
        type,
        userId,
        startDate: start,
        endDate: end,
        limit,
        offset,
      });

      return result;
    } catch (error) {
      this.logger.error('Failed to retrieve tenant events:', error);
      throw new BadRequestException('Failed to retrieve events');
    }
  }

  @Get('security')
  @ApiOperation({ 
    summary: 'Get security events for current tenant', 
    description: 'Returns security-related audit events for the current tenant with pagination support.'
  })
  @ApiQuery({ name: 'limit', required: false, type: Number, description: 'Number of events to return (1-1000)', example: 50 })
  @ApiQuery({ name: 'offset', required: false, type: Number, description: 'Offset for pagination', example: 0 })
  @ApiResponse({ 
    status: 200, 
    description: 'Successfully retrieved security events', 
    type: PaginatedEventsResponseDto 
  })
  @ApiResponse({ status: 400, description: 'Invalid parameters' })
  @ApiResponse({ status: 403, description: 'Insufficient permissions' })
  @UseInterceptors(CacheControlInterceptor)
  async security(
    @Req() req: authTypes.AuthenticatedRequest,
    @Query('limit', new DefaultValuePipe('50'), ParseIntPipe) limit: number,
    @Query('offset', new DefaultValuePipe('0'), ParseIntPipe) offset: number,
  ) {
    const ipAddress = req.ip || req.socket.remoteAddress || 'unknown';
    if (ipAddress && ipAddress !== 'unknown' && await this.ipReputationService.isIPBlocked(ipAddress)) {
      await this.eventLog.logEvent('SECURITY_CSRF_ERROR', {
        userId: req.user.id,
        tenantId: req.tenant?.id,
        metadata: { 
          reason: 'BLOCKED_IP_SECURITY_EVENTS_ACCESS_ATTEMPT',
          endpoint: '/tenant/events/security',
          action: 'GET_TENANT_SECURITY_EVENTS',
        },
        ipAddress: ipAddress,
        userAgent: req.headers['user-agent'] as string,
        severity: 'CRITICAL',
      });
      
      throw new ForbiddenException('Security events access denied - IP address is blocked');
    }

    if (limit < 1 || limit > 1000) {
      throw new BadRequestException('Limit must be between 1 and 1000');
    }
    if (offset < 0) {
      throw new BadRequestException('Offset must be >= 0');
    }

    const tenantId = req.tenant?.id;
    
    if (!tenantId) {
      throw new BadRequestException('Tenant context not available');
    }

    // Log the access attempt
    await this.eventLog.logEvent('AUDIT_TRAIL_ACCESSED', {
      userId: req.user.id,
      tenantId: tenantId,
      metadata: {
        action: 'GET_TENANT_SECURITY_EVENTS',
        limit,
        offset,
      },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'] as string,
      severity: 'INFO',
    });

    try {
      const result: PaginatedResult<any> = await this.eventLog.queryEvents({
        tenantId,
        severity: 'SECURITY',
        limit,
        offset,
      });

      return result;
    } catch (error) {
      this.logger.error('Failed to retrieve security events:', error);
      throw new BadRequestException('Failed to retrieve security events');
    }
  }

  @Get('count')
  @ApiOperation({ 
    summary: 'Get event counts for current tenant', 
    description: 'Returns count of different event types for the current tenant.'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Successfully retrieved event counts',
    type: EventCountsDto
  })
  @ApiResponse({ status: 403, description: 'Insufficient permissions' })
  async count(
    @Req() req: authTypes.AuthenticatedRequest,
  ) {
    const ipAddress = req.ip || req.socket.remoteAddress || 'unknown';
    if (ipAddress && ipAddress !== 'unknown' && await this.ipReputationService.isIPBlocked(ipAddress)) {
      await this.eventLog.logEvent('SECURITY_CSRF_ERROR', {
        userId: req.user.id,
        tenantId: req.tenant?.id,
        metadata: { 
          reason: 'BLOCKED_IP_EVENT_COUNTS_ACCESS_ATTEMPT',
          endpoint: '/tenant/events/count',
          action: 'GET_TENANT_EVENT_COUNTS',
        },
        ipAddress: ipAddress,
        userAgent: req.headers['user-agent'] as string,
        severity: 'CRITICAL',
      });
      
      throw new ForbiddenException('Event counts access denied - IP address is blocked');
    }

    const tenantId = req.tenant?.id;
    
    if (!tenantId) {
      throw new BadRequestException('Tenant context not available');
    }

    // Log the access attempt
    await this.eventLog.logEvent('AUDIT_TRAIL_ACCESSED', {
      userId: req.user.id,
      tenantId: tenantId,
      metadata: {
        action: 'GET_TENANT_EVENT_COUNTS',
      },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'] as string,
      severity: 'INFO',
    });

    try {
      // Get counts for different severity levels
      const [total, security, info, error] = await Promise.all([
        this.eventLog['prisma'].event.count({ where: { tenantId } }),
        this.eventLog['prisma'].event.count({ where: { tenantId, severity: 'SECURITY' } }),
        this.eventLog['prisma'].event.count({ where: { tenantId, severity: 'INFO' } }),
        this.eventLog['prisma'].event.count({ where: { tenantId, severity: 'ERROR' } }),
      ]);

      return {
        total,
        security,
        info,
        error,
      };
    } catch (error) {
      this.logger.error('Failed to retrieve event counts:', error);
      throw new BadRequestException('Failed to retrieve event counts');
    }
  }

  @Get('verify-integrity')
  @Roles('SUPER_ADMIN') // Only super admins can verify integrity
  @ApiOperation({ 
    summary: 'Verify integrity chain for current tenant', 
    description: 'Verifies the integrity hash chain for all events in the current tenant. SUPER_ADMIN only.'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Integrity verification result',
    schema: {
      type: 'object',
      properties: {
        valid: { type: 'boolean' },
        total: { type: 'number' },
        brokenIndex: { type: 'number', nullable: true },
      },
    }
  })
  @ApiResponse({ status: 403, description: 'Insufficient permissions' })
  async verifyIntegrity(
    @Req() req: authTypes.AuthenticatedRequest,
  ) {
    const ipAddress = req.ip || req.socket.remoteAddress || 'unknown';
    if (ipAddress && ipAddress !== 'unknown' && await this.ipReputationService.isIPBlocked(ipAddress)) {
      await this.eventLog.logEvent('SECURITY_CSRF_ERROR', {
        userId: req.user.id,
        tenantId: req.tenant?.id,
        metadata: { 
          reason: 'BLOCKED_IP_INTEGRITY_VERIFICATION_ATTEMPT',
          endpoint: '/tenant/events/verify-integrity',
          action: 'VERIFY_TENANT_INTEGRITY_CHAIN',
        },
        ipAddress: ipAddress,
        userAgent: req.headers['user-agent'] as string,
        severity: 'CRITICAL',
      });
      
      throw new ForbiddenException('Integrity verification denied - IP address is blocked');
    }

    const tenantId = req.tenant?.id;
    
    if (!tenantId) {
      throw new BadRequestException('Tenant context not available');
    }

    // Log the verification attempt
    await this.eventLog.logEvent('AUDIT_TRAIL_ACCESSED', {
      userId: req.user.id,
      tenantId: tenantId,
      metadata: {
        action: 'VERIFY_TENANT_INTEGRITY_CHAIN',
      },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'] as string,
      severity: 'SECURITY',
    });

    try {
      // This would need to be implemented in your service to verify tenant-specific events
      // For now, we'll use the global verification (you might want to add tenant-specific verification)
      const result = await this.eventLog.verifyChain();
      return result;
    } catch (error) {
      this.logger.error('Failed to verify integrity chain:', error);
      throw new BadRequestException('Failed to verify integrity chain');
    }
  }
}