// src/device-fingerprinting/device-fingerprinting.controller.ts
import {
    Controller,
    Get,
    Post,
    Patch,
    Delete,
    Param,
    Body,
    Query,
    UseGuards,
    BadRequestException,
    Logger,
    HttpStatus,
    Req,
    UseInterceptors,
    ClassSerializerInterceptor,
    ForbiddenException,
  } from '@nestjs/common';
  import type { Request } from 'express';
  import {
    ApiTags,
    ApiOperation,
    ApiResponse,
    ApiParam,
    ApiQuery,
    ApiBearerAuth,
    ApiSecurity,
    ApiBody,
  } from '@nestjs/swagger';
  import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
  import { RolesGuard } from '../auth/guards/roles.guard';
  import { TenantGuard } from '../auth/guards/tenant.guard';
  import { CsrfGuard } from '../auth/guards/csrf.guard';
  import { CacheControlInterceptor } from '../interceptors/cache-control.interceptor';
  import { Roles } from '../auth/decorators/roles.decorator';
  import { EventLogService } from '../events/event.service';
  import { DeviceFingerprintingService } from './device-fingerprinting.service';
  import { DeviceAnalysisResult } from './types/device.types';
  
  // Request DTOs
  class DeviceIntelligenceRequestDto {
    userAgent: string;
    ipAddress: string;
    userId?: string;
    sessionId?: string;
    method?: string;
    url?: string;
    responseTime?: number;
  }
  
  // Response DTOs
  class DeviceAnalysisResultDto {
    deviceId: string;
    isBot: boolean;
    confidence: number;
    riskScore: number;
    isSuspicious: boolean;
    indicators: string[];
    recommendation: 'ALLOW' | 'CHALLENGE' | 'BLOCK';
    similarityScore: number;
    matchedDevices: string[];
    isNewDevice: boolean;
    analysis: {
      userAgent: boolean;
      deviceType: boolean;
      browser: boolean;
      os: boolean;
      timing: boolean;
      pattern: boolean;
    };
    firstSeen: Date;
    lastSeen: Date;
  }
  
  @ApiTags('device-intelligence')
  @Controller('device-intelligence')
  @ApiBearerAuth()
  @ApiSecurity('csrf-token')
  @UseInterceptors(ClassSerializerInterceptor)
  @UseGuards(JwtAuthGuard, RolesGuard, CsrfGuard)
  export class DeviceFingerprintingController {
    private readonly logger = new Logger(DeviceFingerprintingController.name);
  
    constructor(
      private readonly deviceFingerprinting: DeviceFingerprintingService,
      private readonly eventLog: EventLogService,
    ) {}
  
    @Post('analyze')
    @UseGuards(JwtAuthGuard, RolesGuard, TenantGuard, CsrfGuard)
    @Roles('ADMIN', 'SUPER_ADMIN')
    @ApiOperation({
      summary: 'Analyze device fingerprint for bot detection',
      description: 'Requires ADMIN or SUPER_ADMIN role. Analyzes device characteristics for bot-like behavior.'
    })
    @ApiBody({ type: DeviceIntelligenceRequestDto })
    @ApiResponse({
      status: 200,
      description: 'Successfully analyzed device for bot behavior',
      type: DeviceAnalysisResultDto
    })
    @ApiResponse({ status: 400, description: 'Invalid parameters' })
    @ApiResponse({ status: 403, description: 'Insufficient permissions' })
    @UseInterceptors(CacheControlInterceptor)
    async analyzeDevice(
      @Req() req: Request & {
        user?: {
          id: string;
          sub: string;
          tenantId: string;
          sessionId: string;
          mfa: boolean;
        };
        tenant?: { id: string; slug?: string };
      },
      @Body() body: DeviceIntelligenceRequestDto,
    ) {
      // Validate required fields
      if (!body.ipAddress) {
        throw new BadRequestException('IP address is required for device analysis');
      }
  
      // Validate IP address format
      if (!this.isValidIP(body.ipAddress)) {
        throw new BadRequestException('Invalid IP address format');
      }
  
      // Validate optional fields
      if (body.responseTime !== undefined && typeof body.responseTime !== 'number') {
        throw new BadRequestException('Response time must be a number');
      }
  
      if (body.method && typeof body.method !== 'string') {
        throw new BadRequestException('Method must be a string');
      }
  
      if (body.url && typeof body.url !== 'string') {
        throw new BadRequestException('URL must be a string');
      }
  
      // Perform device analysis
      const result = await this.deviceFingerprinting.analyzeDeviceForBot(
        body.userId || req.user?.sub || null,
        body.sessionId || req.user?.sessionId || null,
        body.userAgent || null,
        body.ipAddress,
        body.method || 'GET',
        body.url || '/',
        body.responseTime || 0,
      );
  
      // Log the device analysis event
      await this.eventLog.logEvent('AUDIT_TRAIL_ACCESSED', {
        userId: req.user?.sub || null,
        tenantId: req.tenant?.id || null,
        metadata: {
          action: 'ANALYZE_DEVICE_FINGERPRINT',
          ipAddress: body.ipAddress,
          userAgent: body.userAgent,
          method: body.method,
          url: body.url,
          responseTime: body.responseTime,
          result: {
            isBot: result.isBot,
            confidence: result.confidence,
            riskScore: result.riskScore,
            recommendation: result.recommendation,
            indicators: result.indicators,
          },
        },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] as string,
        severity: result.isBot ? 'SECURITY' : 'INFO',
      });
  
      return result;
    }
  
    @Get('stats/:userId')
    @UseGuards(JwtAuthGuard, RolesGuard, TenantGuard, CsrfGuard)
    @Roles('ADMIN', 'SUPER_ADMIN')
    @ApiOperation({
      summary: 'Get device reuse statistics for a user',
      description: 'Requires ADMIN or SUPER_ADMIN role. Returns device reuse statistics for a specific user.'
    })
    @ApiParam({ name: 'userId', description: 'User ID to get device stats for', example: 'user123' })
    @ApiResponse({
      status: 200,
      description: 'Successfully retrieved device reuse statistics',
      schema: {
        type: 'object',
        properties: {
          totalDevices: { type: 'number' },
          activeDevices: { type: 'number' },
          devicePatterns: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                fingerprint: {
                  type: 'object',
                  properties: {
                    userAgent: { type: 'string' },
                    ipAddress: { type: 'string' },
                    os: { type: 'string' },
                    browser: { type: 'string' },
                    deviceType: { type: 'string' },
                  },
                },
                sessionCount: { type: 'number' },
                firstSeen: { type: 'string', format: 'date-time' },
                lastSeen: { type: 'string', format: 'date-time' },
              },
            },
          },
        },
      },
    })
    @ApiResponse({ status: 403, description: 'Insufficient permissions' })
    @ApiResponse({ status: 404, description: 'User not found' })
    @UseInterceptors(CacheControlInterceptor)
    async getDeviceStats(
      @Req() req: Request,
      @Param('userId') userId: string,
    ) {
      if (!userId) {
        throw new BadRequestException('User ID is required');
      }
  
      const stats = await this.deviceFingerprinting.getDeviceReuseStats(userId);
  
      await this.eventLog.logEvent('AUDIT_TRAIL_ACCESSED', {
        userId: req.user?.sub || null,
        tenantId: req.tenant?.id || null,
        metadata: {
          action: 'GET_DEVICE_REUSE_STATS',
          targetUserId: userId,
          statsRetrieved: Object.keys(stats),
        },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] as string,
        severity: 'INFO',
      });
  
      return stats;
    }
  
    private isValidIP(ip: string): boolean {
      // Basic IP validation
      const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
      const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
      const ipv6CompressedRegex = /^([0-9a-fA-F]{1,4}:)*::([0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}$/;
  
      if (ipv4Regex.test(ip)) {
        // Additional validation for IPv4
        const octets = ip.split('.').map(Number);
        return octets.every(octet => octet >= 0 && octet <= 255);
      }
  
      return ipv6Regex.test(ip) || ipv6CompressedRegex.test(ip);
    }
  }