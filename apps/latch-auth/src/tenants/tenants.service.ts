import { Injectable, Logger, NotFoundException, ForbiddenException, BadRequestException, UnauthorizedException, Inject } from '@nestjs/common';
import { generateIntegrityHash } from '@/auth/utils/hash.util';
import { Prisma } from '@prisma/client';
import { Redis } from 'ioredis';
import sanitizeHtml from 'sanitize-html';
import { PrismaService } from '../prisma/prisma.service';
import { CreateTenantDto } from './dto/create-tenant.dto';
import { UpdateTenantDto } from './dto/update-tenant.dto';
@Injectable()
export class TenantsService {
  private readonly logger = new Logger(TenantsService.name);
  @Inject('REDIS') private readonly redis: Redis;

  constructor(private readonly prisma: PrismaService) {}

  async findAll(page: number = 1, limit: number = 50, includeCounts: boolean = false) {
    if (page < 1 || limit < 1 || limit > 100) {
      throw new BadRequestException('Invalid pagination parameters');
    }
  
    const skip = (page - 1) * limit;
    
    // Check cache for the paginated results
    const cacheKey = `tenants:page:${page}:limit:${limit}:counts:${includeCounts}`;
    const cached = await this.redis.get(cacheKey);
    
    if (cached) {
      return JSON.parse(cached);
    }
  
    let selectConfig: any = {
      id: true,
      name: true,
      slug: true,
      status: true,
      createdAt: true,
      updatedAt: true,
      branding: true,
    };
    
    // Only add counts if requested
    if (includeCounts) {
      selectConfig._count = {
        select: {
          users: true,
          Role: true,
          Permission: true,
        },
      };
    }
    
    const [tenants, total] = await Promise.all([
      this.prisma.tenant.findMany({
        skip,
        take: limit,
        select: selectConfig,
        orderBy: { createdAt: 'desc' },
      }),
      this.prisma.tenant.count(),
    ]);
  
    const result = {
      data: tenants,
      meta: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
    };
  
    // Cache the result
    await this.redis.setex(cacheKey, 300, JSON.stringify(result)); // 5 minutes TTL
  
    return result;
  }

async findOne(slug: string, includeStats: boolean = false) {
  // Check cache for basic tenant (without sensitive arrays)
  const basicCacheKey = `tenant:${slug}:basic`;
  const basicCached = await this.redis.get(basicCacheKey);
  
  if (basicCached && !includeStats) {
    return JSON.parse(basicCached);
  }

  // Check cache for tenant with all data (but without stats)
  const withDataCacheKey = `tenant:${slug}:with_data`;
  const withDataCached = await this.redis.get(withDataCacheKey);
  
  let tenant;
  if (withDataCached && !includeStats) {
    tenant = JSON.parse(withDataCached);
  } else {
    // Query the database with all the complex includes
    tenant = await this.prisma.tenant.findUnique({
      where: { slug },
      include: {
        users: {
          select: {
            id: true,
            name: true,
            phone: true,
            email: true,
            isPhoneVerified: true,
            isEmailVerified: true,
            createdAt: true,
          },
          take: 50, // Safe limit
        },
        policies: {
          select: {
            requireMFA: true,
            privilegedUserMFARequired: true,
            roleInheritanceEnabled: true,
            permissionConflictStrategy: true,
            defaultRoleId: true,
            createdAt: true,
            updatedAt: true,
          },
        },
        Role: {
          select: {
            id: true,
            name: true,
            isSystem: true,
            _count: {
              select: { userRoles: true },
            },
          },
          take: 20, // Limit roles returned
        },
        Permission: {
          select: {
            id: true,
            name: true,
            resource: true,
            action: true,
            _count: {
              select: { rolePermissions: true },
            },
          },
          take: 50, // Limit permissions returned
        },
      },
    });

    if (!tenant) {
      throw new NotFoundException(`Tenant with slug "${slug}" not found`);
    }

    // Cache the full tenant data (without stats) for future requests
    await this.redis.setex(withDataCacheKey, 900, JSON.stringify(tenant)); // 15 minutes TTL
  }

  if (includeStats) {
    // Check cache for stats
    const statsCacheKey = `tenant:${slug}:stats`;
    let stats = await this.redis.get(statsCacheKey);
    
    if (!stats) {
      const [userCount, sessionCount, eventCount] = await Promise.all([
        this.prisma.user.count({ where: { tenantId: tenant.id } }),
        this.prisma.session.count({ where: { tenantId: tenant.id } }),
        this.prisma.event.count({ where: { tenantId: tenant.id } }),
      ]);

      stats = JSON.stringify({
        userCount,
        sessionCount,
        eventCount,
        roleCount: tenant.Role.length, // These come from the cached/queried data
        permissionCount: tenant.Permission.length, // These come from the cached/queried data
      });
      
      await this.redis.setex(statsCacheKey, 300, stats); // 5 minutes TTL
    }

    return {
      ...tenant,
      stats: JSON.parse(stats),
    };
  }

  // Return basic tenant without sensitive arrays
  const { Role, Permission, ...basicTenant } = tenant;
  
  // Cache the basic version too
  await this.redis.setex(basicCacheKey, 900, JSON.stringify(basicTenant)); // 15 minutes TTL
  
  return basicTenant;
}

async create(createTenantDto: CreateTenantDto, createdBy?: string) {
  const { name, slug, status = 'ACTIVE', branding, requireMFA, defaultRoleName, security } = createTenantDto;

  // Security: Validate slug format to prevent injection
  if (!/^[a-z0-9][a-z0-9\-_]*[a-z0-9]$/.test(slug)) {
    throw new BadRequestException('Invalid slug format: only lowercase letters, numbers, hyphens, and underscores allowed');
  }

  // Security: Validate name format
  if (!/^[a-zA-Z0-9\s\-_.,&()]{2,100}$/.test(name)) {
    throw new BadRequestException('Invalid tenant name format');
  }

  // Check if slug already exists
  const existingTenant = await this.prisma.tenant.findUnique({
    where: { slug },
  });

  if (existingTenant) {
    throw new BadRequestException(`Tenant with slug "${slug}" already exists`);
  }

  return this.prisma.$transaction(async (tx) => {
    // Create tenant
    const tenant = await tx.tenant.create({
      data: {
        name,
        slug,
        status: status as 'ACTIVE' | 'SUSPENDED',
        branding: branding ? this.sanitizeBranding(branding) : undefined,
      },
      select: {
        id: true,
        name: true,
        slug: true,
        status: true,
        createdAt: true,
        updatedAt: true,
        branding: true,
      },
    });

    let defaultRoleId: string | undefined;

    // Create default role if defaultRoleName is provided
    if (defaultRoleName) {
      const defaultRole = await tx.role.create({
        data: {
          name: defaultRoleName,
          tenantId: tenant.id,
          isSystem: true, // Mark as system role since it's a default
          description: 'Default role assigned to new users',
        },
        select: {
          id: true,
        },
      });
      defaultRoleId = defaultRole.id;
    }

    // Create tenant policy if MFA, default role, or security settings are specified
    if (requireMFA !== undefined || defaultRoleId || security) {
      const policyData: any = {
        tenantId: tenant.id,
        requireMFA: requireMFA ?? false,
        defaultRoleId: defaultRoleId, // Link the default role
        privilegedUserMFARequired: security?.privilegedUserMFARequired ?? true,
        roleInheritanceEnabled: security?.roleInheritanceEnabled ?? true,
        permissionConflictStrategy: security?.permissionConflictStrategy ?? 'DENY_WINS',
        allowedFactors: security?.allowedFactors ?? ['SMS', 'TOTP'],
      };

      // Add security properties that were missing from create
      if (security) {
        if (security.enforcePasswordComplexity !== undefined) {
          policyData.enforcePasswordComplexity = security.enforcePasswordComplexity;
        }
        if (security.passwordMinLength !== undefined) {
          policyData.passwordMinLength = security.passwordMinLength;
        }
        if (security.passwordExpiryDate) {
          policyData.passwordExpiryDate = new Date(security.passwordExpiryDate);
        }
        if (security.maxFailedLoginAttempts !== undefined) {
          policyData.maxFailedLoginAttempts = security.maxFailedLoginAttempts;
        }
        if (security.lockoutDurationSeconds !== undefined) {
          policyData.lockoutDurationSeconds = security.lockoutDurationSeconds;
        }
      }

      await tx.tenantPolicy.create({
        data: policyData, // Pass the policyData as the data property
      });
    }

    // Log security event
    await tx.event.create({
      data: {
        type: 'LOGIN',
        severity: 'INFO',
        tenantId: tenant.id,
        userId: createdBy || null,
        metadata: {
          action: 'TENANT_CREATED',
          tenantSlug: slug,
          createdBy: createdBy,
        },
        integrityHash: this.generateIntegrityHash(`tenant_created_${tenant.id}`),
        createdAt: new Date(),
      },
    });

    this.logger.log(`Created tenant: ${slug} (${tenant.id}) by ${createdBy || 'system'}`);
    await this.invalidateTenantListCache();
    return tenant;
  });
}

  async update(slug: string, updateTenantDto: UpdateTenantDto, updatedBy?: string) {
    const tenant = await this.prisma.tenant.findUnique({
      where: { slug },
      include: { policies: true },
    });

    if (!tenant) {
      throw new NotFoundException(`Tenant with slug "${slug}" not found`);
    }

    return this.prisma.$transaction(async (tx) => {
      const updateData: any = {};
      let policyUpdated = false;

      // Handle basic fields
      if (updateTenantDto.name) {
        if (!/^[a-zA-Z0-9\s\-_.,&()]{2,100}$/.test(updateTenantDto.name)) {
          throw new BadRequestException('Invalid tenant name format');
        }
        updateData.name = updateTenantDto.name;
      }
      if (updateTenantDto.status) {
        updateData.status = updateTenantDto.status;
      }
      if (updateTenantDto.branding) {
        updateData.branding = this.sanitizeBranding(updateTenantDto.branding);
      }

      // Update tenant basic info
      const updatedTenant = await tx.tenant.update({
        where: { slug },
        data: updateData,
        select: {
          id: true,
          name: true,
          slug: true,
          status: true,
          createdAt: true,
          updatedAt: true,
          branding: true,
        },
      });

      // Handle tenant policy updates
if (updateTenantDto.policies || updateTenantDto.requireMFA !== undefined || updateTenantDto.security) {
    const policyData: any = {};
    // let policyUpdated = false;
  
    // Handle policies object fields (MFA, role, permission settings)
    if (updateTenantDto.policies) {
      if (updateTenantDto.policies.requireMFA !== undefined) {
        policyData.requireMFA = updateTenantDto.policies.requireMFA;
        policyUpdated = true;
      }
      if (updateTenantDto.policies.privilegedUserMFARequired !== undefined) {
        policyData.privilegedUserMFARequired = updateTenantDto.policies.privilegedUserMFARequired;
        policyUpdated = true;
      }
      if (updateTenantDto.policies.roleInheritanceEnabled !== undefined) {
        policyData.roleInheritanceEnabled = updateTenantDto.policies.roleInheritanceEnabled;
        policyUpdated = true;
      }
      if (updateTenantDto.policies.permissionConflictStrategy) {
        policyData.permissionConflictStrategy = updateTenantDto.policies.permissionConflictStrategy;
        policyUpdated = true;
      }
      if (updateTenantDto.policies.allowedFactors) {
        policyData.allowedFactors = updateTenantDto.policies.allowedFactors;
        policyUpdated = true;
      }
    }
  
    // Handle security object fields (password, lockout settings)
    if (updateTenantDto.security) {
      if (updateTenantDto.security.enforcePasswordComplexity !== undefined) {
        policyData.enforcePasswordComplexity = updateTenantDto.security.enforcePasswordComplexity;
        policyUpdated = true;
      }
      if (updateTenantDto.security.passwordMinLength !== undefined) {
        policyData.passwordMinLength = updateTenantDto.security.passwordMinLength;
        policyUpdated = true;
      }
      if (updateTenantDto.security.passwordExpiryDate) {
        policyData.passwordExpiryDate = new Date(updateTenantDto.security.passwordExpiryDate);
        policyUpdated = true;
      }
      if (updateTenantDto.security.maxFailedLoginAttempts !== undefined) {
        policyData.maxFailedLoginAttempts = updateTenantDto.security.maxFailedLoginAttempts;
        policyUpdated = true;
      }
      if (updateTenantDto.security.lockoutDurationSeconds !== undefined) {
        policyData.lockoutDurationSeconds = updateTenantDto.security.lockoutDurationSeconds;
        policyUpdated = true;
      }
    }
  
    // Handle direct requireMFA flag (takes precedence over policies.requireMFA if both exist)
    if (updateTenantDto.requireMFA !== undefined) {
      policyData.requireMFA = updateTenantDto.requireMFA;
      policyUpdated = true;
    }
  
    if (policyUpdated) {
      try {
        await tx.tenantPolicy.upsert({
          where: { tenantId: tenant.id },
          update: policyData,
          create: {
            tenantId: tenant.id,
            ...policyData,
          },
        });
  
        // Log security policy update
        await tx.event.create({
          data: {
            type: 'USER_PROFILE_UPDATE',
            severity: 'SECURITY',
            tenantId: tenant.id,
            userId: updatedBy || null,
            metadata: {
              action: 'TENANT_POLICY_UPDATED',
              tenantSlug: slug,
              updatedBy: updatedBy,
              updatedFields: Object.keys(policyData),
            },
            integrityHash: this.generateIntegrityHash(`policy_updated_${tenant.id}_${Date.now()}`),
            createdAt: new Date(),
          },
        });
      } catch (error) {
        this.logger.error(`Failed to update tenant policy for ${slug}:`, error);
        throw new BadRequestException('Failed to update tenant security policies');
      }
    }
  }

      // Log update event
      await tx.event.create({
        data: {
          type: 'USER_PROFILE_UPDATE',
          severity: 'INFO',
          tenantId: tenant.id,
          userId: updatedBy || null,
          metadata: {
            action: 'TENANT_UPDATED',
            tenantSlug: slug,
            updatedBy: updatedBy,
          },
          integrityHash: this.generateIntegrityHash(`tenant_updated_${tenant.id}`),
          createdAt: new Date(),
        },
      });

      this.logger.log(`Updated tenant: ${slug} (${tenant.id}) by ${updatedBy || 'system'}`);

      // Cache invalidation - do this after transaction completes
      await this.redis.del(`tenant:${slug}:basic`);
      await this.redis.del(`tenant:${slug}:with_data`); // Updated key name to match findOne
      await this.redis.del(`tenant:${slug}:stats`);
      await this.invalidateTenantListCache();

      return updatedTenant;
    });
  }

  async remove(slug: string, removedBy?: string) {
    const tenant = await this.prisma.tenant.findUnique({
      where: { slug },
    });

    if (!tenant) {
      throw new NotFoundException(`Tenant with slug "${slug}" not found`);
    }

    if (tenant.status === 'SUSPENDED') {
      throw new BadRequestException(`Tenant "${slug}" is already suspended`);
    }

    // Security: Use transaction for data integrity
    return this.prisma.$transaction(async (tx) => {
      // Soft delete by updating status to SUSPENDED
      const updatedTenant = await tx.tenant.update({
        where: { slug },
        data: { 
          status: 'SUSPENDED',
          updatedAt: new Date(),
        },
        select: {
          id: true,
          name: true,
          slug: true,
          status: true,
          createdAt: true,
          updatedAt: true,
        },
      });

  // Step 2: Revoke ALL active sessions for users belonging to this tenant
      // This ensures users cannot continue accessing resources with existing valid tokens.
      await tx.session.updateMany({
        where: {
          userId: { // Find sessions
            in: (await tx.user.findMany({ // whose userId is in the list of user IDs from the tenant being suspended
              where: { tenantId: tenant.id },
              select: { id: true }, // Only select the ID
            })).map(user => user.id) // Extract the IDs into an array for the 'in' filter
          },
          revoked: false, // Only update sessions that are currently active (not already revoked)
        },
        data: {
          revoked: true, // Mark the session as revoked
          revokedAt: new Date(), // Log when it was revoked
          updatedAt: new Date(), // Update the timestamp
        },
      });

      // Log security event
      await tx.event.create({
        data: {
          type: 'SESSION_REVOKE_ALL',
          severity: 'SECURITY',
          tenantId: tenant.id,
          userId: removedBy || null,
          metadata: {
            action: 'TENANT_SUSPENDED',
            tenantSlug: slug,
            removedBy: removedBy,
          },
          integrityHash: this.generateIntegrityHash(`tenant_suspended_${tenant.id}`),
          createdAt: new Date(),
        },
      });

      this.logger.log(`Suspended tenant: ${slug} (${tenant.id}) by ${removedBy || 'system'}`);

        // At the end of the transaction, before return:
        await this.redis.del(`tenant:${slug}:basic`);
        await this.redis.del(`tenant:${slug}:with_data`);
        await this.redis.del(`tenant:${slug}:stats`);
        await this.invalidateTenantListCache();

      return updatedTenant;
    });
  }

  async activate(slug: string, activatedBy?: string) {
    const tenant = await this.prisma.tenant.findUnique({
      where: { slug },
      select: { status: true, id: true, slug: true },
    });
  
    if (!tenant) {
      throw new NotFoundException(`Tenant with slug "${slug}" not found`);
    }
  
    if (tenant.status === 'ACTIVE') {
      throw new BadRequestException(`Tenant "${slug}" is already active`);
    }
  
    return this.prisma.$transaction(async (tx) => {
      const updatedTenant = await tx.tenant.update({
        where: { slug },
        data: { status: 'ACTIVE' },
        select: {
          id: true,
          name: true,
          slug: true,
          status: true,
          createdAt: true,
          updatedAt: true,
        },
      });
  
      // Log security event within the same transaction
      await tx.event.create({
        data: {
          type: 'LOGIN',
          severity: 'INFO',
          tenantId: tenant.id,
          userId: activatedBy || null, // Fixed: Now passes activatedBy to userId
          metadata: {
            action: 'TENANT_ACTIVATED',
            tenantSlug: slug,
            activatedBy: activatedBy,
          },
          integrityHash: this.generateIntegrityHash(`tenant_activated_${tenant.id}`),
          createdAt: new Date(),
        },
      });
  
      this.logger.log(`Activated tenant: ${slug} (${tenant.id}) by ${activatedBy || 'system'}`);

      // At the end of the transaction, before return:
      await this.redis.del(`tenant:${slug}:basic`);
      await this.redis.del(`tenant:${slug}:with_data`);
      await this.redis.del(`tenant:${slug}:stats`);
      await this.invalidateTenantListCache();

      return updatedTenant;
    });
  }

  async exists(slug: string): Promise<boolean> {
    const count = await this.prisma.tenant.count({
      where: { slug },
    });
    return count > 0;
  }

  async getTenantStats(slug: string) {
    const expectedCacheKey = `tenant:${slug}:stats`;
  
    // 1. Check Redis cache first
    const cachedStats = await this.redis.get(expectedCacheKey);
    if (cachedStats) {
      // For security, still validate tenant exists before returning cached data
      const tenant = await this.prisma.tenant.findUnique({
        where: { slug },
        select: { id: true },
      });
  
      if (!tenant) {
        throw new NotFoundException(`Tenant with slug "${slug}" not found`);
      }
  
      return JSON.parse(cachedStats);
    }
  
    // 2. If not cached, fetch from database
    const tenant = await this.prisma.tenant.findUnique({
      where: { slug },
      select: { id: true },
    });
  
    if (!tenant) {
      throw new NotFoundException(`Tenant with slug "${slug}" not found`);
    }
  
    const [
      userCount,
      sessionCount,
      roleCount,
      permissionCount,
      eventCount,
      securityEventCount
    ] = await Promise.all([
      this.prisma.user.count({ where: { tenantId: tenant.id } }),
      this.prisma.session.count({ where: { tenantId: tenant.id } }),
      this.prisma.role.count({ where: { tenantId: tenant.id } }),
      this.prisma.permission.count({ where: { tenantId: tenant.id } }),
      this.prisma.event.count({ where: { tenantId: tenant.id } }),
      this.prisma.event.count({ 
        where: { 
          tenantId: tenant.id,
          severity: 'SECURITY',
        },
      }),
    ]);
  
    const statsResult = {
      userCount,
      sessionCount,
      roleCount,
      permissionCount,
      eventCount,
      securityEventCount,
    };
  
    // 3. Cache the result before returning
    await this.redis.setex(expectedCacheKey, 300, JSON.stringify(statsResult)); // 5 minutes TTL
  
    return statsResult;
  }

  private async invalidateTenantListCache() {
    // Invalidate first 10 pages of common limits
    const commonLimits = [25, 50, 100];
    for (let page = 1; page <= 10; page++) {
      for (const limit of commonLimits) {
        await this.redis.del(`tenants:page:${page}:limit:${limit}:counts:true`);
        await this.redis.del(`tenants:page:${page}:limit:${limit}:counts:false`);
      }
    }
  }
  
  private sanitizeBranding(branding: any) {
    if (!branding || typeof branding !== 'object') {
      return undefined;
    }

    const sanitized: any = {};

    // Sanitize logoUrl
    if (branding.logoUrl && typeof branding.logoUrl === 'string') {
      try {
        const url = new URL(branding.logoUrl);

        // Only allow HTTPS
        if (url.protocol !== 'https:') {
          throw new Error('Only HTTPS URLs allowed');
        }

        // Block private/internal IP addresses to prevent SSRF
        const hostname = url.hostname.toLowerCase();
        const isPrivateIP = /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)/.test(hostname);
        const isLocalhost = hostname === 'localhost';
        const isInternal = hostname.endsWith('.internal') || hostname.endsWith('.local');

        if (isPrivateIP || isLocalhost || isInternal) {
          throw new Error('Internal/reserved addresses not allowed');
        }

        // Limit URL length
        if (url.href.length > 2048) {
          throw new Error('URL too long');
        }

        sanitized.logoUrl = url.href;
      } catch (error) {
        this.logger.warn(`Invalid logo URL provided: ${branding.logoUrl}. Reason: ${error.message}`);
        // Invalid URL or blocked address, skip silently or log and return undefined based on your policy
        // For this example, we'll skip the field
      }
    }

    // Sanitize primaryColor
    if (branding.primaryColor && typeof branding.primaryColor === 'string') {
      if (/^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/.test(branding.primaryColor)) {
        sanitized.primaryColor = branding.primaryColor;
      } else {
         this.logger.warn(`Invalid primary color format: ${branding.primaryColor}`);
      }
    }

    // Sanitize secondaryColor
    if (branding.secondaryColor && typeof branding.secondaryColor === 'string') {
      if (/^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/.test(branding.secondaryColor)) {
        sanitized.secondaryColor = branding.secondaryColor;
      } else {
         this.logger.warn(`Invalid secondary color format: ${branding.secondaryColor}`);
      }
    }

    // Sanitize companyName with more robust XSS prevention
 // Sanitize companyName with more robust XSS prevention
if (branding.companyName && typeof branding.companyName === 'string') {
  // Use sanitize-html to remove all HTML tags and attributes
  // It will also handle escaping of special characters in text nodes
  const cleanCompanyName = sanitizeHtml(branding.companyName, {
    allowedTags: [], // No tags allowed, only text nodes
    allowedAttributes: {}, // No attributes allowed
  });

  // Truncate after sanitization
  sanitized.companyName = cleanCompanyName.substring(0, 100).trim();
}
    return sanitized;
  }

  private generateIntegrityHash(data: string): string {
    return generateIntegrityHash(data);
  }
}
