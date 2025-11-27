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
  import { BotDetectionService } from './bot-detection.service';
  import { BotDetectionResult } from './types/bot.types';
  
  // Response DTOs
  class BotDetectionResultDto {
    isBot: boolean;
    confidence: number;
    indicators: string[];
    riskScore: number;
    recommendation: 'ALLOW' | 'CHALLENGE' | 'BLOCK';
    analysis: {
      userAgent: boolean;
      timing: boolean;
      navigation: boolean;
      requestPattern: boolean;
      sessionBehavior: boolean;
    };
  }
  
  class BotStatsDto {
    totalBotDetections: number;
    botConfidenceAverage: number;
    lastBotDetection: Date | null;
    topIndicators: Array<{ indicator: string; count: number }>;
    recentDetections: Array<{
      id: string;
      timestamp: Date;
      ipAddress: string;
      userAgent: string;
      riskScore: number;
      confidence: number;
    }>;
  }
  
  class BotDetectionConfigDto {
    id: string;
    tenantId: string;
    name: string;
    thresholds: {
      low: number;
      medium: number;
      high: number;
      critical: number;
    };
    enabled: boolean;
    customPatterns: string[];
    createdAt: Date;
    updatedAt: Date;
  }
  
  @ApiTags('bot-detection')
  @Controller('v1/bot-detection')
  @ApiBearerAuth()
  @ApiSecurity('csrf-token')
  @UseInterceptors(ClassSerializerInterceptor)
  @UseGuards(JwtAuthGuard, RolesGuard, CsrfGuard)
  export class BotDetectionController {
    private readonly logger = new Logger(BotDetectionController.name);
  
    constructor(
      private readonly botDetection: BotDetectionService,
      private readonly eventLog: EventLogService,
    ) {}
  
    @Get('analyze')
  @UseGuards(JwtAuthGuard, RolesGuard, TenantGuard, CsrfGuard)
  @Roles('ADMIN', 'SUPER_ADMIN')
  @ApiOperation({ 
    summary: 'Analyze request for bot behavior', 
    description: 'Requires ADMIN or SUPER_ADMIN role. Analyzes request patterns for bot-like behavior.'
  })
  @ApiQuery({ name: 'ipAddress', required: true, type: String, description: 'IP address to analyze', example: '192.168.1.100' })
  @ApiQuery({ name: 'userAgent', required: false, type: String, description: 'User agent string to analyze', example: 'Mozilla/5.0...' })
  @ApiQuery({ name: 'method', required: false, type: String, description: 'HTTP method', example: 'GET' })
  @ApiQuery({ name: 'url', required: false, type: String, description: 'URL to analyze', example: '/api/users' })
  @ApiResponse({ 
    status: 200, 
    description: 'Successfully analyzed request for bot behavior',
    type: BotDetectionResultDto 
  })
  @ApiResponse({ status: 400, description: 'Invalid parameters' })
  @ApiResponse({ status: 403, description: 'Insufficient permissions' })
  @UseInterceptors(CacheControlInterceptor)
  async analyzeRequest(
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
    @Query('ipAddress') ipAddress: string,
    @Query('userAgent') userAgent?: string,
    @Query('method') method: string = 'GET',
    @Query('url') url: string = '/',
  ) {
    if (!ipAddress) {
      throw new BadRequestException('IP address is required for bot analysis');
    }

    // Validate IP address format
    if (!this.isValidIP(ipAddress)) {
      throw new BadRequestException('Invalid IP address format');
    }

    // Now TypeScript knows that req.user.sessionId exists
    const result = await this.botDetection.analyzeRequest(
      req.user?.sub || null,        // userId from JWT payload
      req.user?.sessionId || null,  // sessionId from JWT payload
      ipAddress,
      userAgent || null,
      method,
      url,
    );

    await this.eventLog.logEvent('AUDIT_TRAIL_ACCESSED', {
      userId: req.user?.sub || null,
      tenantId: req.tenant?.id || null,
      metadata: {
        action: 'ANALYZE_BOT_REQUEST',
        ipAddress,
        userAgent,
        method,
        url,
        result: {
          isBot: result.isBot,
          confidence: result.confidence,
          riskScore: result.riskScore,
          recommendation: result.recommendation,
        },
      },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'] as string,
      severity: 'INFO',
    });

    return result;
  }
  
    @Get('stats/:ipAddress')
    @UseGuards(JwtAuthGuard, RolesGuard, TenantGuard, CsrfGuard)
    @Roles('ADMIN', 'SUPER_ADMIN')
    @ApiOperation({ 
      summary: 'Get bot detection statistics for an IP', 
      description: 'Requires ADMIN or SUPER_ADMIN role. Returns bot detection statistics for a specific IP address.'
    })
    @ApiParam({ name: 'ipAddress', description: 'IP address to get stats for', example: '192.168.1.100' })
    @ApiResponse({ 
      status: 200, 
      description: 'Successfully retrieved bot detection statistics',
      type: BotStatsDto 
    })
    @ApiResponse({ status: 403, description: 'Insufficient permissions' })
    @ApiResponse({ status: 404, description: 'IP not found' })
    @UseInterceptors(CacheControlInterceptor)
    async getBotStats(
      @Req() req: Request,
      @Param('ipAddress') ipAddress: string,
    ) {
      if (!this.isValidIP(ipAddress)) {
        throw new BadRequestException('Invalid IP address format');
      }
  
      const stats = await this.botDetection.getBotStats(ipAddress);
  
      await this.eventLog.logEvent('AUDIT_TRAIL_ACCESSED', {
        userId: req.user?.sub || null,
        tenantId: req.tenant?.id || null,
        metadata:{
          action: 'GET_BOT_STATS',
          targetIpAddress: ipAddress,
          statsRetrieved: Object.keys(stats),
        },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] as string,
        severity: 'INFO',
      });
  
      return stats;
    }
  
    @Get('recent')
    @UseGuards(JwtAuthGuard, RolesGuard, TenantGuard, CsrfGuard)
    @Roles('ADMIN', 'SUPER_ADMIN')
    @ApiOperation({ 
      summary: 'Get recent bot detections', 
      description: 'Requires ADMIN or SUPER_ADMIN role. Returns recent bot detection events with statistics.'
    })
    @ApiQuery({ name: 'limit', required: false, type: Number, description: 'Number of events to return (1-100)', example: 50 })
    @ApiQuery({ name: 'offset', required: false, type: Number, description: 'Offset for pagination', example: 0 })
    @ApiQuery({ name: 'severity', required: false, type: String, description: 'Filter by severity level', example: 'HIGH' })
    @ApiResponse({ 
      status: 200, 
      description: 'Successfully retrieved recent bot detections',
      schema: {
        type: 'object',
        properties: {
          data: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                id: { type: 'string' },
                timestamp: { type: 'string', format: 'date-time' },
                ipAddress: { type: 'string' },
                userAgent: { type: 'string' },
                riskScore: { type: 'number' },
                confidence: { type: 'number' },
                indicators: {
                  type: 'array',
                  items: { type: 'string' },
                },
                recommendation: { type: 'string', enum: ['ALLOW', 'CHALLENGE', 'BLOCK'] },
              },
            },
          },
          meta: {
            type: 'object',
            properties: {
              total: { type: 'number' },
              limit: { type: 'number' },
              offset: { type: 'number' },
              hasNext: { type: 'boolean' },
            },
          },
        },
      },
    })
    @ApiResponse({ status: 400, description: 'Invalid parameters' })
    @ApiResponse({ status: 403, description: 'Insufficient permissions' })
    @UseInterceptors(CacheControlInterceptor)
    async getRecentBotDetections(
      @Req() req: Request,
      @Query('limit') limit: number = 50,
      @Query('offset') offset: number = 0,
      @Query('severity') severity?: string,
    ) {
      // Validate parameters
      if (limit < 1 || limit > 100) {
        throw new BadRequestException('Limit must be between 1 and 100');
      }
      if (offset < 0) {
        throw new BadRequestException('Offset must be >= 0');
      }
  
      // This would need to be implemented in the service
      // For now, return empty result
      const result = {
        data: [],
        meta: {
          total: 0,
          limit,
          offset,
          hasNext: false,
        },
      };
  
      await this.eventLog.logEvent('AUDIT_TRAIL_ACCESSED', {
        userId: req.user?.sub || null,
        tenantId: req.tenant?.id || null,
        metadata:{
          action: 'GET_RECENT_BOT_DETECTIONS',
          limit,
          offset,
          severity,
        },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] as string,
        severity: 'INFO',
      });
  
      return result;
    }
  
    @Post('challenge/:ipAddress')
    @UseGuards(JwtAuthGuard, RolesGuard, TenantGuard, CsrfGuard)
    @Roles('SUPER_ADMIN')
    @ApiOperation({ 
      summary: 'Challenge a suspected bot IP', 
      description: 'Requires SUPER_ADMIN role. Forces a bot challenge for a specific IP address.'
    })
    @ApiParam({ name: 'ipAddress', description: 'IP address to challenge', example: '192.168.1.100' })
    @ApiResponse({ 
      status: 200, 
      description: 'Successfully challenged IP address' 
    })
    @ApiResponse({ status: 403, description: 'Insufficient permissions' })
    @ApiResponse({ status: 404, description: 'IP not found' })
    async challengeBot(
      @Req() req: Request,
      @Param('ipAddress') ipAddress: string,
    ) {
      if (!this.isValidIP(ipAddress)) {
        throw new BadRequestException('Invalid IP address format');
      }
  
      const success = await this.botDetection.challengeBot({
        ip: ipAddress,
        user: req.user,
        tenant: req.tenant,
      });
  
      await this.eventLog.logEvent('LOGIN', {
        userId: req.user?.sub || null,
        tenantId: req.tenant?.id || null,
        metadata:{
          action: 'CHALLENGE_BOT_IP',
          targetIpAddress: ipAddress,
          success,
        },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] as string,
        severity: 'INFO',
      });
  
      return { success, message: success ? 'Bot challenge initiated' : 'Bot challenge failed' };
    }
  
    @Get('config')
    @UseGuards(JwtAuthGuard, RolesGuard, TenantGuard, CsrfGuard)
    @Roles('SUPER_ADMIN')
    @ApiOperation({ 
      summary: 'Get bot detection configuration', 
      description: 'Requires SUPER_ADMIN role. Returns current bot detection configuration.'
    })
    @ApiResponse({ 
      status: 200, 
      description: 'Successfully retrieved bot detection configuration',
      type: BotDetectionConfigDto 
    })
    @ApiResponse({ status: 403, description: 'Insufficient permissions' })
    async getBotDetectionConfig(@Req() req: Request) {
      // This would return the current configuration
      // Implementation would depend on your config storage
      const config = {
        id: 'default-config',
        tenantId: 'system',
        name: 'Default Bot Detection Configuration',
        thresholds: {
          low: 0.3,
          medium: 0.6,
          high: 0.8,
          critical: 0.95,
        },
        enabled: true,
        customPatterns: [],
        createdAt: new Date(),
        updatedAt: new Date(),
      };
  
      await this.eventLog.logEvent('AUDIT_TRAIL_ACCESSED', {
        userId: req.user?.sub || null,
        tenantId: req.tenant?.id || null,
        metadata:{
          action: 'GET_BOT_DETECTION_CONFIG',
        },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] as string,
        severity: 'INFO',
      });
  
      return config;
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