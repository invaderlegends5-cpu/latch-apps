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
    ForbiddenException,
    HttpStatus,
    UseInterceptors,
    ClassSerializerInterceptor,
    Req,
  } from '@nestjs/common';
  import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
  import { RolesGuard } from '../auth/guards/roles.guard';
  import { TenantGuard } from '../auth/guards/tenant.guard';
  import { Roles } from '../auth/decorators/roles.decorator';
  import { EventLogService } from '../events/event.service';
  import { RateLimitingService } from './rate-limiting.service';
  import { TenantRateLimitProfile, RateLimitConfig } from './types/rate-limit.types';
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
    getSchemaPath,
  } from '@nestjs/swagger';
  
  // Create DTOs for Swagger
  class RateLimitConfigDto {
    limit: number;
    windowMs: number;
    type: 'fixed' | 'sliding' | 'token-bucket';
    burstAllowance?: number;
    penalty?: {
      type: 'block' | 'delay' | 'captcha';
      durationMs?: number;
      multiplier?: number;
    };
  }
  
  class TenantRateLimitProfileDto {
    id: string;
    tenantId: string;
    name: string;
    limits: {
      otpRequest: RateLimitConfigDto;
      otpVerify: RateLimitConfigDto;
      refresh: RateLimitConfigDto;
      login: RateLimitConfigDto;
      apiRequests: RateLimitConfigDto;
      fileUploads: RateLimitConfigDto;
    };
    createdAt: Date;
    updatedAt: Date;
    isActive: boolean;
  }
  
  @Controller('v1/rate-limiting')
  @ApiTags('rate-limiting')
  @ApiBearerAuth()
  @ApiSecurity('csrf-token')
  @UseInterceptors(ClassSerializerInterceptor)
  @UseGuards(JwtAuthGuard, RolesGuard, TenantGuard)
  export class RateLimitingController {
    private readonly logger = new Logger(RateLimitingController.name);
  
    constructor(
      private readonly rateLimitService: RateLimitingService,
      private readonly eventLog: EventLogService,
    ) {}
  
    @Get('profile')
    @Roles('ADMIN', 'SUPER_ADMIN')
    @ApiOperation({ 
      summary: 'Get tenant rate limit profile', 
      description: 'Requires ADMIN or SUPER_ADMIN role. Returns the current rate limit profile for the tenant.'
    })
    @ApiResponse({ 
      status: 200, 
      description: 'Successfully retrieved tenant rate limit profile',
      schema: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          tenantId: { type: 'string' },
          name: { type: 'string' },
          limits: {
            type: 'object',
            properties: {
              otpRequest: { $ref: getSchemaPath(RateLimitConfigDto) },
              otpVerify: { $ref: getSchemaPath(RateLimitConfigDto) },
              refresh: { $ref: getSchemaPath(RateLimitConfigDto) },
              login: { $ref: getSchemaPath(RateLimitConfigDto) },
              apiRequests: { $ref: getSchemaPath(RateLimitConfigDto) },
              fileUploads: { $ref: getSchemaPath(RateLimitConfigDto) },
            },
          },
          createdAt: { type: 'string', format: 'date-time' },
          updatedAt: { type: 'string', format: 'date-time' },
          isActive: { type: 'boolean' },
        },
      },
    })
    @ApiResponse({ status: 403, description: 'Insufficient permissions' })
    async getTenantProfile(
      @Req() req: Request,
    ) {
      const tenantId = req.tenant?.id;
      if (!tenantId) {
        throw new BadRequestException('Tenant context not available');
      }
  
      const profile = await this.rateLimitService.getTenantRateLimitProfile(tenantId);
  
      await this.eventLog.logEvent('AUDIT_TRAIL_ACCESSED', {
        userId: req.user?.id || null,
        tenantId,
        metadata: {
          action: 'GET_TENANT_RATE_LIMIT_PROFILE',
          profileExists: !!profile,
        },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] as string,
        severity: 'INFO',
      });
  
      if (!profile) {
        throw new BadRequestException('No rate limit profile found for tenant');
      }
  
      return profile;
    }
  
    @Post('profile')
    @Roles('ADMIN', 'SUPER_ADMIN')
    @ApiOperation({ 
      summary: 'Create or update tenant rate limit profile', 
      description: 'Requires ADMIN or SUPER_ADMIN role. Creates or updates the rate limit profile for the tenant.'
    })
    @ApiBody({
      schema: {
        type: 'object',
        properties: {
          name: { type: 'string', example: 'standard' },
          limits: {
            type: 'object',
            properties: {
              otpRequest: { $ref: getSchemaPath(RateLimitConfigDto) },
              otpVerify: { $ref: getSchemaPath(RateLimitConfigDto) },
              refresh: { $ref: getSchemaPath(RateLimitConfigDto) },
              login: { $ref: getSchemaPath(RateLimitConfigDto) },
              apiRequests: { $ref: getSchemaPath(RateLimitConfigDto) },
              fileUploads: { $ref: getSchemaPath(RateLimitConfigDto) },
            },
          },
          isActive: { type: 'boolean', default: true },
        },
        required: ['name', 'limits'],
      },
    })
    @ApiResponse({ 
      status: 200, 
      description: 'Successfully created or updated tenant rate limit profile',
      schema: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          tenantId: { type: 'string' },
          name: { type: 'string' },
          limits: {
            type: 'object',
            properties: {
              otpRequest: { $ref: getSchemaPath(RateLimitConfigDto) },
              otpVerify: { $ref: getSchemaPath(RateLimitConfigDto) },
              refresh: { $ref: getSchemaPath(RateLimitConfigDto) },
              login: { $ref: getSchemaPath(RateLimitConfigDto) },
              apiRequests: { $ref: getSchemaPath(RateLimitConfigDto) },
              fileUploads: { $ref: getSchemaPath(RateLimitConfigDto) },
            },
          },
          createdAt: { type: 'string', format: 'date-time' },
          updatedAt: { type: 'string', format: 'date-time' },
          isActive: { type: 'boolean' },
        },
      },
    })
    @ApiResponse({ status: 400, description: 'Invalid input' })
    @ApiResponse({ status: 403, description: 'Insufficient permissions' })
    async createOrUpdateProfile(
      @Req() req: Request,
      @Body() profileData: Omit<TenantRateLimitProfile, 'id' | 'createdAt' | 'updatedAt'>, // Fixed type
    ) {
      const tenantId = req.tenant?.id;
      if (!tenantId) {
        throw new BadRequestException('Tenant context not available');
      }
  
      // Validate profile data
      if (!profileData.name || !profileData.limits) {
        throw new BadRequestException('Profile name and limits are required');
      }
  
      const profile = await this.rateLimitService.createOrUpdateTenantProfile(
        tenantId,
        profileData
      );
  
      await this.eventLog.logEvent('USER_PROFILE_UPDATE', {
        userId: req.user?.id || null,
        tenantId,
        metadata: {
          action: 'UPDATE_TENANT_RATE_LIMIT_PROFILE',
          profileId: profile.id,
          profileName: profile.name,
          updatedFields: Object.keys(profileData),
        },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] as string,
        severity: 'SECURITY',
      });
  
      return profile;
    }
  
    @Get('usage')
    @Roles('ADMIN', 'SUPER_ADMIN')
    @ApiOperation({ 
      summary: 'Get rate limit usage statistics', 
      description: 'Requires ADMIN or SUPER_ADMIN role. Returns rate limit usage statistics for the tenant.'
    })
    @ApiQuery({ name: 'endpoint', required: false, type: String, description: 'Filter by specific endpoint', example: '/auth/login' })
    @ApiQuery({ name: 'days', required: false, type: Number, description: 'Number of days to look back', example: 7 })
    @ApiResponse({ 
      status: 200, 
      description: 'Successfully retrieved rate limit usage statistics',
      schema: {
        type: 'object',
        properties: {
          tenantId: { type: 'string' },
          endpoint: { type: 'string' },
          days: { type: 'number' },
          startDate: { type: 'string', format: 'date-time' },
          usageStats: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                tenantId: { type: 'string' },
                endpoint: { type: 'string' },
                windowStart: { type: 'string', format: 'date-time' },
                count: { type: 'number' },
                resetTime: { type: 'string', format: 'date-time' },
                remaining: { type: 'number' },
              },
            },
          },
        },
      },
    })
    @ApiResponse({ status: 403, description: 'Insufficient permissions' })
    async getUsageStats(
      @Req() req: Request,
      @Query('endpoint') endpoint?: string,
      @Query('days') days: number = 7,
    ) {
      const tenantId = req.tenant?.id;
      if (!tenantId) {
        throw new BadRequestException('Tenant context not available');
      }
  
      const startDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
  
      const usageStats = await this.rateLimitService.getRateLimitUsage(tenantId, endpoint);
  
      await this.eventLog.logEvent('AUDIT_TRAIL_ACCESSED', {
        userId: req.user?.id || null,
        tenantId,
        metadata:{
          action: 'GET_RATE_LIMIT_USAGE_STATS',
          endpoint,
          days,
          statsCount: usageStats.length,
        },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] as string,
        severity: 'INFO',
      });
  
      return {
        tenantId,
        endpoint,
        days,
        startDate,
        usageStats,
      };
    }
  
    @Get('profiles')
    @Roles('SUPER_ADMIN')
    @ApiOperation({ 
      summary: 'Get all tenant rate limit profiles', 
      description: 'Requires SUPER_ADMIN role. Returns all rate limit profiles across all tenants.'
    })
    @ApiResponse({ 
      status: 200, 
      description: 'Successfully retrieved all tenant rate limit profiles',
      schema: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            tenantId: { type: 'string' },
            name: { type: 'string' },
            limits: {
              type: 'object',
              properties: {
                otpRequest: { $ref: getSchemaPath(RateLimitConfigDto) },
                otpVerify: { $ref: getSchemaPath(RateLimitConfigDto) },
                refresh: { $ref: getSchemaPath(RateLimitConfigDto) },
                login: { $ref: getSchemaPath(RateLimitConfigDto) },
                apiRequests: { $ref: getSchemaPath(RateLimitConfigDto) },
                fileUploads: { $ref: getSchemaPath(RateLimitConfigDto) },
              },
            },
            createdAt: { type: 'string', format: 'date-time' },
            updatedAt: { type: 'string', format: 'date-time' },
            isActive: { type: 'boolean' },
          },
        },
      },
    })
    @ApiResponse({ status: 403, description: 'Insufficient permissions' })
    async getAllProfiles(
      @Req() req: Request,
    ) {
      const profiles = await this.rateLimitService.getAllTenantProfiles();
  
      await this.eventLog.logEvent('AUDIT_TRAIL_ACCESSED', {
        userId: req.user?.id || null, 
        tenantId: null,
        metadata:{
          action: 'GET_ALL_RATE_LIMIT_PROFILES',
          totalProfiles: profiles.length,
        },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] as string,
        severity: 'INFO',
      });
  
      return profiles;
    }
  
    @Patch('profile/:profileId/activate')
    @Roles('ADMIN', 'SUPER_ADMIN')
    @ApiOperation({ 
      summary: 'Activate a rate limit profile', 
      description: 'Requires ADMIN or SUPER_ADMIN role. Activates a rate limit profile.'
    })
    @ApiParam({ name: 'profileId', description: 'ID of the profile to activate', example: 'profile-uuid' })
    @ApiResponse({ 
      status: 200, 
      description: 'Successfully activated rate limit profile'
    })
    @ApiResponse({ status: 403, description: 'Insufficient permissions' })
    @ApiResponse({ status: 404, description: 'Profile not found' })
    async activateProfile(
      @Req() req: Request,
      @Param('profileId') profileId: string,
    ) {
      // This would need to be implemented in the service
      // For now, return success
      await this.eventLog.logEvent('LOGIN', {
        userId: req.user?.id || null,
        tenantId: req.tenant?.id,
        metadata:{
          action: 'ACTIVATE_RATE_LIMIT_PROFILE',
          profileId,
        },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] as string,
        severity: 'INFO',
      });
  
      return { message: 'Profile activation not yet implemented' };
    }
  }