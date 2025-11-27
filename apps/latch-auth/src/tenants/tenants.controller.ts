import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Body,
  Param,
  UseGuards,
  Query,
  BadRequestException,
  Logger,
  HttpStatus,
  Req,
  HttpCode,
  DefaultValuePipe,
  ParseIntPipe,
  ValidationPipe,
  UseInterceptors,
  ClassSerializerInterceptor,
  ForbiddenException,
  InternalServerErrorException,
  NotFoundException,
 } from '@nestjs/common';
import express from 'express';
import { 
  ApiTags, 
  ApiOperation, 
  ApiResponse, 
  ApiParam, 
  ApiQuery, 
  ApiBearerAuth,
  ApiSecurity,
  ApiExtraModels,
  getSchemaPath
} from '@nestjs/swagger';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { TenantGuard } from '../auth/guards/tenant.guard';
import { CsrfGuard } from '../auth/guards/csrf.guard';
import { CacheControlInterceptor } from '../interceptors/cache-control.interceptor';
import { Roles } from '../auth/decorators/roles.decorator';
import { EventLogService } from '../events/event.service';
import { TenantsService } from './tenants.service';
import { CreateTenantDto } from './dto/create-tenant.dto';
import { UpdateTenantDto } from './dto/update-tenant.dto';
import { IPReputationService } from '../ip-reputation/ip-reputation.service';

// Enhanced response DTOs for better API documentation
class TenantResponseDto {
  id: string;
  name: string;
  slug: string;
  status: string;
  createdAt: Date;
  updatedAt: Date;
  branding?: any;
  _count?: {
    users: number;
    Role: number;
    Permission: number;
  };
}

class PaginatedTenantResponseDto {
  data: TenantResponseDto[];
  meta: {
    page: number;
    limit: number;
    total: number;
    pages: number;
  };
}

class TenantStatsResponseDto {
  userCount: number;
  sessionCount: number;
  roleCount: number;
  permissionCount: number;
  eventCount: number;
  securityEventCount: number;
}

@ApiTags('tenants')
@Controller('v1/tenants')
@ApiBearerAuth()
@ApiSecurity('csrf-token')
@UseInterceptors(ClassSerializerInterceptor)
export class TenantsController {
  private readonly logger = new Logger(TenantsController.name);

  constructor(
    private readonly tenantsService: TenantsService,
    private readonly eventLogService: EventLogService,
    private readonly ipReputationService: IPReputationService,
  ) {}

  @Get()
  @UseGuards(JwtAuthGuard, RolesGuard, TenantGuard)
  @Roles('ADMIN', 'SUPER_ADMIN')
  @ApiOperation({
    summary: 'List all tenants with pagination and optional counts',
    description: 'Requires ADMIN or SUPER_ADMIN role. Returns paginated tenant list with optional user/role/permission counts.'
  })
  @ApiQuery({ name: 'page', required: false, type: Number, description: 'Page number (default: 1)', example: 1 })
  @ApiQuery({ name: 'limit', required: false, type: Number, description: 'Items per page (default: 50, max: 100)', example: 50 })
  @ApiQuery({ name: 'includeCounts', required: false, type: Boolean, description: 'Include user/role/permission counts', example: false })
  @ApiResponse({
    status: 200,
    description: 'Successfully retrieved paginated tenants',
    type: PaginatedTenantResponseDto
  })
  @ApiResponse({ status: 400, description: 'Invalid pagination parameters' })
  @ApiResponse({ status: 403, description: 'Insufficient permissions' })
  @UseInterceptors(CacheControlInterceptor) // Enable caching for read operations
  async findAll(
    @Query('page', new DefaultValuePipe('1'), ParseIntPipe) page: string,
    @Query('limit', new DefaultValuePipe('50'), ParseIntPipe) limit: string,
    @Query('includeCounts', new DefaultValuePipe('false')) includeCounts: string,
    @Req() req: express.Request,
  ) {
    const ipAddress = req.ip || req.socket.remoteAddress || 'unknown';
    if (ipAddress && ipAddress !== 'unknown' && await this.ipReputationService.isIPBlocked(ipAddress)) {
      await this.eventLogService.logEvent('SECURITY_CSRF_ERROR', {
        userId: req.user?.sub || null,
        tenantId: req.tenant?.id || null,
        metadata: { 
          reason: 'BLOCKED_IP_TENANT_ACCESS_ATTEMPT',
          endpoint: '/tenants',
          action: 'LIST_TENANTS',
        },
        ipAddress: ipAddress,
        userAgent: req.headers['user-agent'] as string,
        severity: 'CRITICAL',
      });
      
      throw new ForbiddenException('Tenant access denied - IP address is blocked');
    }

    const pageNum = parseInt(page, 10);
    const limitNum = parseInt(limit, 10);
    const includeCountsBool = includeCounts === 'true';

    // Input validation
    if (pageNum < 1 || limitNum < 1 || limitNum > 100) {
      await this.eventLogService.logEvent('TENANT_VALIDATION_ERROR', {
        userId: req.user?.sub || null,
        tenantId: req.tenant?.id || null,
        metadata: {
          reason: 'invalid_pagination_params',
          page: pageNum,
          limit: limitNum,
        },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] as string,
        severity: 'SECURITY',
      });
      throw new BadRequestException('Invalid pagination parameters');
    }

    // --- ENHANCEMENT: Log the attempt *before* the service call ---
    await this.eventLogService.logEvent('USER_LIST_ATTEMPTED', {
      userId: req.user?.sub || null,
      tenantId: req.tenant?.id || null,
      metadata: {
        action: 'LIST_TENANTS',
        page: pageNum,
        limit: limitNum,
        includeCounts: includeCountsBool,
      },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'] as string,
      severity: 'INFO', // Or 'SECURITY' depending on your classification
    });
    // --- END ENHANCEMENT ---

    const result = await this.tenantsService.findAll(pageNum, limitNum, includeCountsBool);

    // --- ENHANCEMENT: Check for undefined result (added previously) ---
    if (!result || !result.meta || typeof result.meta.total === 'undefined') {
      this.logger.error(`TenantsService.findAll returned invalid structure:`, result);
      await this.eventLogService.logEvent('INTERNAL_ERROR', {
        userId: req.user?.sub || null,
        tenantId: req.tenant?.id || null,
        metadata: {
          reason: 'invalid_service_response',
          action: 'LIST_TENANTS',
          serviceResponse: result, // Log the invalid response for debugging (be careful with sensitive data)
        },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] as string,
        severity: 'CRITICAL', // Or 'ERROR'
      });
      throw new InternalServerErrorException('An error occurred while retrieving tenants.');
    }
    // --- END ENHANCEMENT ---

    // Log successful outcome *after* the service call (original behavior)
    await this.eventLogService.logEvent('USER_LIST_ACCESSED', {
      userId: req.user?.sub || null,
      tenantId: req.tenant?.id || null,
      metadata: {
        action: 'LIST_TENANTS',
        page: pageNum,
        limit: limitNum,
        includeCounts: includeCountsBool,
        total: result.meta.total, // Safe to access now
      },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'] as string,
      severity: 'INFO',
    });

    return result;
  }

  @Post()
  @UseGuards(JwtAuthGuard, RolesGuard, CsrfGuard)
  @Roles('SUPER_ADMIN')
  @ApiOperation({ 
    summary: 'Create a new tenant', 
    description: 'Requires SUPER_ADMIN role. Creates a new tenant with associated default role and policy.'
  })
  @ApiResponse({ 
    status: 201, 
    description: 'Tenant created successfully', 
    type: TenantResponseDto 
  })
  @ApiResponse({ status: 400, description: 'Invalid input or tenant already exists' })
  @ApiResponse({ status: 403, description: 'Insufficient permissions' })
  async create(
    @Body(new ValidationPipe({ 
      whitelist: true, 
      forbidNonWhitelisted: true,
      transform: true 
    })) createTenantDto: CreateTenantDto,
    @Req() req: express.Request,
  ) {
    const ipAddress = req.ip || req.socket.remoteAddress || 'unknown';
    if (ipAddress && ipAddress !== 'unknown' && await this.ipReputationService.isIPBlocked(ipAddress)) {
      await this.eventLogService.logEvent('SECURITY_CSRF_ERROR', {
        userId: req.user?.sub || null,
        tenantId: null,
        metadata: { 
          reason: 'BLOCKED_IP_TENANT_CREATION_ATTEMPT',
          endpoint: '/tenants',
          action: 'CREATE_TENANT',
          tenantName: createTenantDto.name,
          tenantSlug: createTenantDto.slug,
        },
        ipAddress: ipAddress,
        userAgent: req.headers['user-agent'] as string,
        severity: 'CRITICAL',
      });
      
      throw new ForbiddenException('Tenant creation denied - IP address is blocked');
    }

     // --- ADD THIS LOG ---
  this.logger.log(`[DEBUG] TenantsController.create method entered. User: ${req.user?.sub}, Tenant: ${req.tenant?.id}, URL: ${req.url}, DTO slug: ${createTenantDto.slug}`);
  // --- END ADD ---

  this.logger.log(`Create endpoint called with DTO: ${JSON.stringify(createTenantDto, null, 2)}, Request User: ${JSON.stringify(req.user, null, 2)}, Request Tenant: ${JSON.stringify(req.tenant, null, 2)}`);
  this.logger.log(`[DEBUG] TenantsController.create method entered. User: ${req.user?.sub}, Tenant: ${req.tenant?.id}, URL: ${req.url}, DTO slug: ${createTenantDto.slug}`);
    // Pre-validation logging
    await this.eventLogService.logEvent('USER_PROFILE_UPDATE', {
      userId: req.user?.sub,
      tenantId: null,
      metadata: {
        action: 'TENANT_CREATION_ATTEMPT',
        tenantSlug: createTenantDto.slug,
        tenantName: createTenantDto.name,
      },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'] as string,
      severity: 'SECURITY',
    });
  
    this.logger.log(`Calling tenantsService.create with DTO: ${JSON.stringify(createTenantDto)} and userId: ${req.user?.sub}`);
    const result = await this.tenantsService.create(createTenantDto, req.user?.sub);
    this.logger.log(`tenantsService.create returned: ${JSON.stringify(result, null, 2)}`);
  
    if (!result || typeof result.id === 'undefined') {
      // --- ENHANCEMENT: More detailed error logging ---
      const errorMessage = `TenantsService.create returned invalid structure (result=${result}, result.id=${result?.id}):`;
      this.logger.error(errorMessage, result); // Log the error message and the invalid result object
  
      // Additional detailed logging for debugging
      this.logger.error(`Detailed validation failure:`, {
        hasResult: result !== null && result !== undefined,
        resultType: typeof result,
        resultKeys: result ? Object.keys(result) : 'N/A',
        hasIdProperty: result ? 'id' in result : false,
        idValue: result?.id,
        idType: result?.id ? typeof result.id : 'N/A'
      });
  
      await this.eventLogService.logEvent('INTERNAL_ERROR', {
        userId: req.user?.sub,
        tenantId: null, // No tenant ID as creation failed/returned invalidly
        metadata: { // Fixed: was 'meta'
          reason: 'invalid_service_response',
          action: 'CREATE_TENANT',
          serviceResponse: result, // Log the invalid response for debugging (be careful with sensitive data)
          validationDetails: {
            hasResult: result !== null && result !== undefined,
            resultType: typeof result,
            hasIdProperty: result ? 'id' in result : false,
            idValue: result?.id,
            idType: result?.id ? typeof result.id : 'N/A'
          }
        },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] as string,
        severity: 'CRITICAL', // Or 'ERROR'
      });
      
      this.logger.error(`Controller decided to throw InternalServerErrorException due to invalid service result.`);
      // --- END ENHANCEMENT ---
  
      // Depending on security posture, throw a generic error or InternalServerErrorException
      throw new InternalServerErrorException('An error occurred while creating the tenant.');
    }
    
    this.logger.log(`Creating success log event for result ID: ${result.id}, Slug: ${result.slug}`);
    await this.eventLogService.logEvent('AUDIT_TRAIL_ACCESSED', {
      userId: req.user?.sub,
      tenantId: result.id,
      metadata: {
        action: 'CREATE_TENANT',
        tenantSlug: result.slug,
        tenantId: result.id,
      },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'] as string,
      severity: 'SECURITY',
    });
  
    this.logger.log(`Returning result from create: ${JSON.stringify(result, null, 2)}`);
    return result;
  }
  
  @Get(':slug')
  @UseGuards(JwtAuthGuard, TenantGuard)
  @ApiOperation({ 
    summary: 'Get tenant details by slug', 
    description: 'Accessible to tenant members (with tenant isolation) or SUPER_ADMINs. Can optionally include statistics.'
  })
  @ApiParam({ name: 'slug', description: 'Tenant slug', example: 'acme-corp' })
  @ApiQuery({ name: 'includeStats', required: false, type: Boolean, description: 'Include tenant statistics', example: false })
  @ApiResponse({ 
    status: 200, 
    description: 'Tenant retrieved successfully', 
    type: TenantResponseDto 
  })
  @ApiResponse({ status: 404, description: 'Tenant not found' })
  @ApiResponse({ status: 403, description: 'Cannot access another tenant' })
  @UseInterceptors(CacheControlInterceptor) // Cache tenant details
  async findOne(
    @Param('slug') slug: string,
    @Query('includeStats', new DefaultValuePipe('false')) includeStats: string,
    @Req() req: express.Request,
  ) {
    const ipAddress = req.ip || req.socket.remoteAddress || 'unknown';
    if (ipAddress && ipAddress !== 'unknown' && await this.ipReputationService.isIPBlocked(ipAddress)) {
      await this.eventLogService.logEvent('SECURITY_CSRF_ERROR', {
        userId: req.user?.sub || null,
        tenantId: req.tenant?.id || null,
        metadata: { 
          reason: 'BLOCKED_IP_TENANT_ACCESS_ATTEMPT',
          endpoint: `/tenants/${slug}`,
          action: 'GET_TENANT',
          targetTenant: slug,
        },
        ipAddress: ipAddress,
        userAgent: req.headers['user-agent'] as string,
        severity: 'CRITICAL',
      });
      
      throw new ForbiddenException('Tenant access denied - IP address is blocked');
    }

    const includeStatsBool = includeStats === 'true';
    
    // Validate slug format
    if (!/^[a-zA-Z0-9-_]+$/.test(slug)) {
      await this.eventLogService.logEvent('TENANT_VALIDATION_ERROR', {
        userId: req.user?.sub,
        tenantId: req.tenant?.id,
        metadata: {
          reason: 'invalid_slug_format',
          requestedSlug: slug,
        },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] as string,
        severity: 'SECURITY',
      });
      throw new BadRequestException('Invalid tenant slug format');
    }

    // Tenant isolation check
    if (req.tenant?.slug !== slug ) {
      await this.eventLogService.logEvent('TENANT_MISMATCH', {
        userId: req.user?.sub,
        tenantId: req.tenant?.id,
        metadata: {
          reason: 'unauthorized_tenant_access',
          requestedTenant: slug,
          userTenant: req.tenant?.slug,
        },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] as string,
        severity: 'SECURITY',
      });
      throw new ForbiddenException('Cannot access another tenant');
    }

    const result = await this.tenantsService.findOne(slug, includeStatsBool);

    // --- ENHANCEMENT: Check for undefined result ---
    if (!result || typeof result.id === 'undefined') {
      this.logger.error(`TenantsService.findOne returned invalid structure:`, result);
      await this.eventLogService.logEvent('INTERNAL_ERROR', {
        userId: req.user?.sub,
        tenantId: req.tenant?.id, // Use the tenant from the request context
        metadata: {
          reason: 'invalid_service_response',
          action: 'GET_TENANT',
          serviceResponse: result,
          requestedTenantSlug: slug,
        },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] as string,
        severity: 'CRITICAL',
      });
      throw new InternalServerErrorException('An error occurred while retrieving the tenant.');
    }
    // --- END ENHANCEMENT ---
    
    await this.eventLogService.logEvent('USER_DATA_ACCESSED', {
      userId: req.user?.sub,
      tenantId: result.id, // Safe to access now
      metadata: {
        action: 'GET_TENANT',
        tenantSlug: slug,
        includeStats: includeStatsBool,
      },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'] as string,
      severity: 'INFO',
    });

    return result;
  }

  @Patch(':slug')
  @UseGuards(JwtAuthGuard, RolesGuard, TenantGuard, CsrfGuard)
  @Roles('ADMIN', 'SUPER_ADMIN')
  @ApiOperation({ 
    summary: 'Update tenant details', 
    description: 'Requires ADMIN or SUPER_ADMIN role. Updates tenant information and associated policies.'
  })
  @ApiParam({ name: 'slug', description: 'Tenant slug', example: 'acme-corp' })
  @ApiResponse({ 
    status: 200, 
    description: 'Tenant updated successfully', 
    type: TenantResponseDto 
  })
  @ApiResponse({ status: 400, description: 'Invalid input' })
  @ApiResponse({ status: 404, description: 'Tenant not found' })
  @ApiResponse({ status: 403, description: 'Cannot update another tenant or insufficient permissions' })
  async update(
    @Param('slug') slug: string,
    @Body(new ValidationPipe({ 
      whitelist: true, 
      forbidNonWhitelisted: true,
      transform: true 
    })) updateTenantDto: UpdateTenantDto,
    @Req() req: express.Request,
  ) {
    const ipAddress = req.ip || req.socket.remoteAddress || 'unknown';
    if (ipAddress && ipAddress !== 'unknown' && await this.ipReputationService.isIPBlocked(ipAddress)) {
      await this.eventLogService.logEvent('SECURITY_CSRF_ERROR', {
        userId: req.user?.sub || null,
        tenantId: req.tenant?.id || null,
        metadata: { 
          reason: 'BLOCKED_IP_TENANT_UPDATE_ATTEMPT',
          endpoint: `/tenants/${slug}`,
          action: 'UPDATE_TENANT',
          targetTenant: slug,
        },
        ipAddress: ipAddress,
        userAgent: req.headers['user-agent'] as string,
        severity: 'CRITICAL',
      });
      
      throw new ForbiddenException('Tenant update denied - IP address is blocked');
    }

    console.log('[TenantsController.update] Method entered. User:', req.user?.sub, 'Tenant ID:', req.tenant?.id, 'Requested Slug:', slug, 'Received DTO:', updateTenantDto);
    // Validate slug format
    if (!/^[a-zA-Z0-9-_]+$/.test(slug)) {
      console.log('[TenantsController.update] Slug validation failed for slug:', slug);
      await this.eventLogService.logEvent('TENANT_VALIDATION_ERROR', {
        userId: req.user?.sub,
        tenantId: req.tenant?.id,
        metadata: {
          reason: 'invalid_slug_format',
          requestedSlug: slug,
        },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] as string,
        severity: 'SECURITY',
      });
      throw new BadRequestException('Invalid tenant slug format');
    }

    console.log('[TenantsController.update] Slug format validation passed for slug:', slug);
    // Tenant isolation check
    if (req.tenant?.slug !== slug) {
      console.log('[TenantsController.update] Tenant isolation failed. req.tenant?.slug:', req.tenant?.slug, 'vs slug param:', slug);
      await this.eventLogService.logEvent('TENANT_MISMATCH', {
        userId: req.user?.sub,
        tenantId: req.tenant?.id,
        metadata: {
          reason: 'unauthorized_tenant_update',
          requestedTenant: slug,
          userTenant: req.tenant?.slug,
        },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] as string,
        severity: 'SECURITY',
      });
      throw new ForbiddenException('Cannot update another tenant');
    }
    console.log('[TenantsController.update] Tenant isolation check passed. req.tenant?.slug matches slug param:', slug);

    // Log update attempt
    console.log('[TenantsController.update] Logging update attempt for slug:', slug, 'with DTO keys:', Object.keys(updateTenantDto));
    await this.eventLogService.logEvent('USER_PROFILE_UPDATE', {
      userId: req.user?.sub,
      tenantId: req.tenant?.id,
      metadata: {
        action: 'TENANT_UPDATE_ATTEMPT',
        tenantSlug: slug,
        updatedFields: Object.keys(updateTenantDto),
      },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'] as string,
      severity: 'SECURITY',
    });

    console.log('[TenantsController.update] Calling service.update with slug:', slug, 'and DTO:', updateTenantDto);
    const result = await this.tenantsService.update(slug, updateTenantDto, req.user?.sub);
    console.log('[TenantsController.update] Service.update returned result:', result);

    // --- ENHANCEMENT: Check for undefined result ---
    if (!result || typeof result.id === 'undefined') {
      console.log('[TenantsController.update] Service returned invalid structure:', result);
      this.logger.error(`TenantsService.update returned invalid structure:`, result);
      await this.eventLogService.logEvent('INTERNAL_ERROR', {
        userId: req.user?.sub,
        tenantId: req.tenant?.id, // Use the tenant from the request context
        metadata: {
          reason: 'invalid_service_response',
          action: 'UPDATE_TENANT',
          serviceResponse: result,
          requestedTenantSlug: slug,
        },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] as string,
        severity: 'CRITICAL',
      });
      throw new InternalServerErrorException('An error occurred while updating the tenant.');
    }
    // --- END ENHANCEMENT ---
    
    console.log('[TenantsController.update] Logging successful update for slug:', slug);
    await this.eventLogService.logEvent('USER_PROFILE_UPDATE', {
      userId: req.user?.sub,
      tenantId: result.id, // Safe to access now
      metadata: {
        action: 'UPDATE_TENANT',
        tenantSlug: slug,
        updatedFields: Object.keys(updateTenantDto),
      },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'] as string,
      severity: 'SECURITY',
    });
    console.log('[TenantsController.update] Method completed successfully, returning result.');
    return result;
  }

  @Delete(':slug')
  @UseGuards(JwtAuthGuard, RolesGuard, TenantGuard, CsrfGuard)
  @Roles('SUPER_ADMIN')
  @ApiOperation({ 
    summary: 'Deactivate tenant (soft delete)', 
    description: 'Requires SUPER_ADMIN role. Soft deletes the tenant by changing status to SUSPENDED.'
  })
  @ApiParam({ name: 'slug', description: 'Tenant slug', example: 'acme-corp' })
  @ApiResponse({ 
    status: 200, 
    description: 'Tenant deactivated successfully', 
    type: TenantResponseDto 
  })
  @ApiResponse({ status: 404, description: 'Tenant not found' })
  @ApiResponse({ status: 403, description: 'Insufficient permissions' })
  @HttpCode(HttpStatus.OK) // Return 200 instead of 204 for consistency
//   async remove(
//     @Param('slug') slug: string,
//     @Req() req: express.Request,
//   ) {

// console.log('[TenantsController.remove] Method entered. User:', req.user?.sub, 'Tenant:', req.tenant?.id, 'Requested Slug:', slug);

//     // Validate slug format
//     if (!/^[a-zA-Z0-9-_]+$/.test(slug)) {
//     console.log('[TenantsController.remove] Slug validation failed for slug:', slug);
//       await this.eventLogService.logEvent('TENANT_VALIDATION_ERROR', {
//         userId: req.user?.sub,
//         tenantId: req.tenant?.id,
//         metadata: {
//           reason: 'invalid_slug_format',
//           requestedSlug: slug,
//         },
//         ipAddress: req.ip,
//         userAgent: req.headers['user-agent'] as string,
//         severity: 'SECURITY',
//       });
//       throw new BadRequestException('Invalid tenant slug format');
//     }
//     console.log('[TenantsController.remove] Slug validation passed. Calling service...');

//     const result = await this.tenantsService.remove(slug, req.user?.sub);

//     // --- ENHANCEMENT: Check for undefined result ---
//     if (!result || typeof result.id === 'undefined') {
//       console.log('[TenantsController.remove] Service returned invalid structure:', result); 
//       this.logger.error(`TenantsService.remove returned invalid structure:`, result);
//       await this.eventLogService.logEvent('INTERNAL_ERROR', {
//         userId: req.user?.sub,
//         tenantId: null, // Or determine from input if deletion context is needed
//         metadata: {
//           reason: 'invalid_service_response',
//           action: 'DEACTIVATE_TENANT', // Or REMOVE_TENANT
//           serviceResponse: result,
//           requestedTenantSlug: slug,
//         },
//         ipAddress: req.ip,
//         userAgent: req.headers['user-agent'] as string,
//         severity: 'CRITICAL',
//       });
//       console.log('[TenantsController.remove] Throwing InternalServerErrorException due to invalid service result.');
//       throw new InternalServerErrorException('An error occurred while deactivating the tenant.');
//     }
//     // --- END ENHANCEMENT ---

//     console.log('[TenantsController.remove] Service result is valid, proceeding to log success.');
//     await this.eventLogService.logEvent('SESSION_REVOKE_ALL', {
//       userId: req.user?.sub,
//       tenantId: result.id, // Safe to access now
//       metadata: {
//         action: 'DEACTIVATE_TENANT',
//         tenantSlug: slug,
//       },
//       ipAddress: req.ip,
//       userAgent: req.headers['user-agent'] as string,
//       severity: 'SECURITY',
//     });
// console.log('[TenantsController.remove] Method completed successfully.');
//     return result;
//   }

async remove(
  @Param('slug') slug: string,
  @Req() req: express.Request,
) {
  const ipAddress = req.ip || req.socket.remoteAddress || 'unknown';
  if (ipAddress && ipAddress !== 'unknown' && await this.ipReputationService.isIPBlocked(ipAddress)) {
    await this.eventLogService.logEvent('SECURITY_CSRF_ERROR', {
      userId: req.user?.sub || null,
      tenantId: req.tenant?.id || null,
      metadata: { 
        reason: 'BLOCKED_IP_TENANT_DEACTIVATION_ATTEMPT',
        endpoint: `/tenants/${slug}`,
        action: 'DEACTIVATE_TENANT',
        targetTenant: slug,
      },
      ipAddress: ipAddress,
      userAgent: req.headers['user-agent'] as string,
      severity: 'CRITICAL',
    });
    
    throw new ForbiddenException('Tenant deactivation denied - IP address is blocked');
  }

  console.log('[TenantsController.remove] Method entered. User:', req.user?.sub, 'Tenant:', req.tenant?.id, 'Requested Slug:', slug);

  // Validate slug format
  if (!/^[a-zA-Z0-9-_]+$/.test(slug)) {
    console.log('[TenantsController.remove] Slug validation failed for slug:', slug);
    await this.eventLogService.logEvent('TENANT_VALIDATION_ERROR', {
      userId: req.user?.sub,
      tenantId: req.tenant?.id,
      metadata: {
        reason: 'invalid_slug_format',
        requestedSlug: slug,
      },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'] as string,
      severity: 'SECURITY',
    });
    throw new BadRequestException('Invalid tenant slug format');
  }

  console.log('[TenantsController.remove] Slug validation passed. Calling service...');

  let result: any; // Declare result variable
  try {
    result = await this.tenantsService.remove(slug, req.user?.sub);
  } catch (error) {
    // Re-throw specific service errors that should be propagated to the client
    // Ensure NotFoundException and other relevant exceptions from the service are handled correctly
    if (error instanceof NotFoundException || error instanceof BadRequestException) {
      console.log(`[TenantsController.remove] Service threw ${error.constructor.name}: ${error.message}`);
      // Log potential internal error if remove was called with a slug that doesn't exist,
      // although this might be expected behavior if the client provides a bad slug.
      // Consider if a specific audit log for "attempt to remove non-existent tenant" is needed.
      // For now, just re-throw the service's specific exception.
      throw error;
    }
    // Optionally, log other unexpected errors from the service
    this.logger.error(`Unexpected error from TenantsService.remove:`, error);
    // Re-throw other errors or handle them as needed, potentially as InternalServerErrorException
    throw error; // Or potentially a generic InternalServerErrorException if desired for unknown errors
  }

  // --- ENHANCEMENT: Check for undefined result (this check should now be less likely to trigger due to catch block) ---
  // This check is primarily for scenarios where the service *returns* an invalid object,
  // not where it throws an exception.
  if (!result || typeof result.id === 'undefined') {
    console.log('[TenantsController.remove] Service returned invalid structure:', result);
    this.logger.error(`TenantsService.remove returned invalid structure:`, result);
    await this.eventLogService.logEvent('INTERNAL_ERROR', {
      userId: req.user?.sub,
      tenantId: null, // Or determine from input if deletion context is needed
      metadata: {
        reason: 'invalid_service_response',
        action: 'DEACTIVATE_TENANT', // Or REMOVE_TENANT
        serviceResponse: result,
        requestedTenantSlug: slug,
      },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'] as string,
      severity: 'CRITICAL',
    });
    console.log('[TenantsController.remove] Throwing InternalServerErrorException due to invalid service result.');
    throw new InternalServerErrorException('An error occurred while deactivating the tenant.');
  }
  // --- END ENHANCEMENT ---

  console.log('[TenantsController.remove] Service result is valid, proceeding to log success.');
  await this.eventLogService.logEvent('SESSION_REVOKE_ALL', {
    userId: req.user?.sub,
    tenantId: result.id, // Safe to access now
    metadata: {
      action: 'DEACTIVATE_TENANT',
      tenantSlug: slug,
    },
    ipAddress: req.ip,
    userAgent: req.headers['user-agent'] as string,
    severity: 'SECURITY',
  });
  console.log('[TenantsController.remove] Method completed successfully.');
  return result;
}

  @Get(':slug/stats')
  @UseGuards(JwtAuthGuard, TenantGuard)
  @ApiOperation({ 
    summary: 'Get tenant statistics', 
    description: 'Accessible to tenant members or SUPER_ADMINs. Returns comprehensive tenant usage statistics.'
  })
  @ApiParam({ name: 'slug', description: 'Tenant slug', example: 'acme-corp' })
  @ApiResponse({ 
    status: 200, 
    description: 'Tenant statistics retrieved', 
    type: TenantStatsResponseDto 
  })
  @ApiResponse({ status: 404, description: 'Tenant not found' })
  @ApiResponse({ status: 403, description: 'Cannot access another tenant\'s statistics' })
  @UseInterceptors(CacheControlInterceptor) // Cache stats
  async getStats(
    @Param('slug') slug: string,
    @Req() req: express.Request,
  ) {
    const ipAddress = req.ip || req.socket.remoteAddress || 'unknown';
    if (ipAddress && ipAddress !== 'unknown' && await this.ipReputationService.isIPBlocked(ipAddress)) {
      await this.eventLogService.logEvent('SECURITY_CSRF_ERROR', {
        userId: req.user?.sub || null,
        tenantId: req.tenant?.id || null,
        metadata: { 
          reason: 'BLOCKED_IP_TENANT_STATS_ACCESS_ATTEMPT',
          endpoint: `/tenants/${slug}/stats`,
          action: 'GET_TENANT_STATS',
          targetTenant: slug,
        },
        ipAddress: ipAddress,
        userAgent: req.headers['user-agent'] as string,
        severity: 'CRITICAL',
      });
      
      throw new ForbiddenException('Tenant stats access denied - IP address is blocked');
    }

    // Validate slug format
    if (!/^[a-zA-Z0-9-_]+$/.test(slug)) {
      await this.eventLogService.logEvent('TENANT_VALIDATION_ERROR', {
        userId: req.user?.sub,
        tenantId: req.tenant?.id,
        metadata: {
          reason: 'invalid_slug_format',
          requestedSlug: slug,
        },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] as string,
        severity: 'SECURITY',
      });
      throw new BadRequestException('Invalid tenant slug format');
    }

    // Tenant isolation check
    if (req.tenant?.slug !== slug) {
      await this.eventLogService.logEvent('AUDIT_TRAIL_ACCESS_ATTEMPTED', {
        userId: req.user?.sub,
        tenantId: req.tenant?.id,
        metadata: {
          reason: 'unauthorized_stats_access',
          requestedTenant: slug,
          userTenant: req.tenant?.slug,
        },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] as string,
        severity: 'SECURITY',
      });
      throw new ForbiddenException('Cannot access another tenant\'s statistics');
    }

    const result = await this.tenantsService.getTenantStats(slug);

    // --- ENHANCEMENT: Check for undefined result ---
    if (!result) {
      this.logger.error(`TenantsService.getTenantStats returned invalid structure:`, result);
      await this.eventLogService.logEvent('INTERNAL_ERROR', {
        userId: req.user?.sub,
        tenantId: req.tenant?.id, // Use the tenant from the request context
        metadata: {
          reason: 'invalid_service_response',
          action: 'GET_TENANT_STATS',
          serviceResponse: result,
          requestedTenantSlug: slug,
        },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] as string,
        severity: 'CRITICAL',
      });
      throw new InternalServerErrorException('An error occurred while retrieving tenant statistics.');
    }
    // --- END ENHANCEMENT ---
    
    await this.eventLogService.logEvent('AUDIT_TRAIL_ACCESSED', {
      userId: req.user?.sub,
      tenantId: req.tenant?.id, // Use tenant from request context for stats access
      metadata: {
        action: 'GET_TENANT_STATS',
        tenantSlug: slug,
        statsRetrieved: Object.keys(result),
      },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'] as string,
      severity: 'INFO',
    });

    return result;
  }

  @Post(':slug/activate')
  @UseGuards(JwtAuthGuard, RolesGuard, TenantGuard, CsrfGuard)
  @Roles('SUPER_ADMIN')
  @ApiOperation({ 
    summary: 'Activate a previously deactivated tenant', 
    description: 'Requires SUPER_ADMIN role. Reactivates a suspended tenant.'
  })
  @ApiParam({ name: 'slug', description: 'Tenant slug', example: 'acme-corp' })
  @ApiResponse({ 
    status: 200, 
    description: 'Tenant activated successfully', 
    type: TenantResponseDto 
  })
  @ApiResponse({ status: 404, description: 'Tenant not found' })
  @ApiResponse({ status: 403, description: 'Insufficient permissions' })
  async activate(
    @Param('slug') slug: string,
    @Req() req: express.Request,
  ) {
    const ipAddress = req.ip || req.socket.remoteAddress || 'unknown';
    if (ipAddress && ipAddress !== 'unknown' && await this.ipReputationService.isIPBlocked(ipAddress)) {
      await this.eventLogService.logEvent('SECURITY_CSRF_ERROR', {
        userId: req.user?.sub || null,
        tenantId: req.tenant?.id || null,
        metadata: { 
          reason: 'BLOCKED_IP_TENANT_ACTIVATION_ATTEMPT',
          endpoint: `/tenants/${slug}/activate`,
          action: 'ACTIVATE_TENANT',
          targetTenant: slug,
        },
        ipAddress: ipAddress,
        userAgent: req.headers['user-agent'] as string,
        severity: 'CRITICAL',
      });
      
      throw new ForbiddenException('Tenant activation denied - IP address is blocked');
    }
    
    // Validate slug format
    if (!/^[a-zA-Z0-9-_]+$/.test(slug)) {
      await this.eventLogService.logEvent('TENANT_VALIDATION_ERROR', {
        userId: req.user?.sub,
        tenantId: req.tenant?.id,
        metadata: {
          reason: 'invalid_slug_format',
          requestedSlug: slug,
        },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] as string,
        severity: 'SECURITY',
      });
      throw new BadRequestException('Invalid tenant slug format');
    }

    const result = await this.tenantsService.activate(slug, req.user?.sub);

    // --- ENHANCEMENT: Check for undefined result ---
    if (!result || typeof result.id === 'undefined') {
      this.logger.error(`TenantsService.activate returned invalid structure:`, result);
      await this.eventLogService.logEvent('INTERNAL_ERROR', {
        userId: req.user?.sub,
        tenantId: null, // Or determine from input if activation context is needed
        metadata: {
          reason: 'invalid_service_response',
          action: 'ACTIVATE_TENANT',
          serviceResponse: result,
          requestedTenantSlug: slug,
        },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] as string,
        severity: 'CRITICAL',
      });
      throw new InternalServerErrorException('An error occurred while activating the tenant.');
    }
    // --- END ENHANCEMENT ---
    
    await this.eventLogService.logEvent('LOGIN', {
      userId: req.user?.sub,
      tenantId: result.id, // Safe to access now
      metadata: {
        action: 'ACTIVATE_TENANT',
        tenantSlug: slug,
      },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'] as string,
      severity: 'INFO',
    });

    return result;
  }
}