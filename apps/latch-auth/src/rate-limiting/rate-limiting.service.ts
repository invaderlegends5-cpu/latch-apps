import { Injectable, Logger, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';
import { EventLogService } from '../events/event.service';
import { RedisService } from '../redis/redis.service';
import { TenantRateLimitProfile, RateLimitConfig, RateLimitUsage, RateLimitCondition } from './types/rate-limit.types';
import { ConditionType } from '../events/event.types';
import * as crypto from 'crypto';

@Injectable()
export class RateLimitingService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(RateLimitingService.name);
  private readonly cachePrefix = 'rate-limit:';
  private readonly usageCachePrefix = 'rate-usage:';
  private readonly defaultProfiles: TenantRateLimitProfile[] = [
    {
      id: 'default-standard',
      tenantId: 'default',
      name: 'standard',
      limits: {
        otpRequest: { limit: 3, windowMs: 5 * 60 * 1000, type: 'fixed' }, // 3 per 5 min
        otpVerify: { limit: 6, windowMs: 10 * 60 * 1000, type: 'fixed' }, // 6 per 10 min
        refresh: { limit: 20, windowMs: 60 * 1000, type: 'fixed' }, // 20 per 1 min
        login: { limit: 5, windowMs: 15 * 60 * 1000, type: 'fixed' }, // 5 per 15 min
        apiRequests: { limit: 100, windowMs: 60 * 1000, type: 'sliding' }, // 100 per 1 min sliding
        fileUploads: { limit: 10, windowMs: 60 * 60 * 1000, type: 'fixed' }, // 10 per hour
      },
      createdAt: new Date(),
      updatedAt: new Date(),
      isActive: true,
    },
    {
      id: 'default-premium',
      tenantId: 'default',
      name: 'premium',
      limits: {
        otpRequest: { limit: 5, windowMs: 5 * 60 * 1000, type: 'fixed' },
        otpVerify: { limit: 10, windowMs: 10 * 60 * 1000, type: 'fixed' },
        refresh: { limit: 50, windowMs: 60 * 1000, type: 'fixed' },
        login: { limit: 10, windowMs: 15 * 60 * 1000, type: 'fixed' },
        apiRequests: { limit: 500, windowMs: 60 * 1000, type: 'sliding' },
        fileUploads: { limit: 50, windowMs: 60 * 60 * 1000, type: 'fixed' },
      },
      createdAt: new Date(),
      updatedAt: new Date(),
      isActive: true,
    },
  ];

  constructor(
    private readonly prisma: PrismaService,
    private readonly eventLog: EventLogService,
    private readonly redis: RedisService,
    private readonly configService: ConfigService,
  ) {}

  async onModuleInit() {
    await this.initialize();
    this.logger.log('Rate Limiting Service initialized');
  }

  async onModuleDestroy() {
    this.logger.log('Rate Limiting Service destroyed');
  }

  private async initialize() {
    // Ensure default profiles exist
    await this.ensureDefaultProfiles();
    
    // Warm up cache with existing profiles
    await this.warmupCache();
  }

  /**
   * Check if a request is allowed based on tenant-specific rate limits
   */
  async isRequestAllowed(
    tenantId: string,
    endpoint: string,
    ipAddress: string,
    userId?: string,
  ): Promise<{ allowed: boolean; remaining: number; resetTime: Date; retryAfter?: number }> {
    try {
      // Get tenant-specific rate limit profile
      const profile = await this.getTenantRateLimitProfile(tenantId);
      if (!profile) {
        this.logger.warn(`No rate limit profile found for tenant ${tenantId}, using default`);
        return { allowed: true, remaining: -1, resetTime: new Date() };
      }

      // Get rate limit config for this endpoint
      const config = this.getRateLimitConfig(profile, endpoint);
      if (!config) {
        // No specific limit for this endpoint, allow
        return { allowed: true, remaining: -1, resetTime: new Date() };
      }

      // Calculate rate limit key
      const rateLimitKey = this.generateRateLimitKey(tenantId, endpoint, ipAddress, userId);
      
      // Check rate limit based on algorithm type
      let result: { allowed: boolean; remaining: number; resetTime: Date; retryAfter?: number };
      
      switch (config.type) {
        case 'fixed':
          result = await this.checkFixedWindowRateLimit(rateLimitKey, config);
          break;
        case 'sliding':
          result = await this.checkSlidingWindowRateLimit(rateLimitKey, config);
          break;
        case 'token-bucket':
          result = await this.checkTokenBucketRateLimit(rateLimitKey, config);
          break;
        default:
          result = { allowed: true, remaining: -1, resetTime: new Date() };
      }

      // Log rate limit check
      await this.eventLog.logEvent(result.allowed ? 'USER_LIST_ACCESSED' : 'REFRESH_FAILED', {
        userId: userId || null,
        tenantId,
        metadata: {
          action: 'RATE_LIMIT_CHECK',
          endpoint,
          ipAddress,
          rateLimitKey,
          config,
          result,
        },
        ipAddress,
        userAgent: null,
        severity: result.allowed ? 'INFO' : 'SECURITY',
      });

      return result;
    } catch (error) {
      this.logger.error('Error checking rate limit:', error);
      // Fail open - if rate limiting fails, allow request but log
      return { allowed: true, remaining: -1, resetTime: new Date() };
    }
  }

  /**
   * Apply rate limit based on permission conditions
   */
  async applyRateLimitFromPermission(
    tenantId: string,
    condition: RateLimitCondition,
    ipAddress: string,
    userId?: string,
  ): Promise<{ allowed: boolean; remaining: number; resetTime: Date; retryAfter?: number }> {
    const { endpoint, limit, windowMs, algorithm } = condition.value;
    
    const config: RateLimitConfig = {
      limit,
      windowMs,
      type: algorithm,
    };

    const rateLimitKey = this.generateRateLimitKey(tenantId, endpoint, ipAddress, userId);
    
    let result: { allowed: boolean; remaining: number; resetTime: Date; retryAfter?: number };
    
    switch (algorithm) {
      case 'fixed':
        result = await this.checkFixedWindowRateLimit(rateLimitKey, config);
        break;
      case 'sliding':
        result = await this.checkSlidingWindowRateLimit(rateLimitKey, config);
        break;
      case 'token-bucket':
        result = await this.checkTokenBucketRateLimit(rateLimitKey, config);
        break;
      default:
        result = { allowed: true, remaining: -1, resetTime: new Date() };
    }

    return result;
  }

  /**
   * Get rate limit condition from permission system
   */
 async getRateLimitConditionFromPermission(permissionCondition: any): Promise<RateLimitCondition | null> {
    if (permissionCondition.conditionType === 'RATE_LIMITED') {
      return {
        conditionType: permissionCondition.conditionType,
        value: permissionCondition.value,
        description: permissionCondition.description,
      };
    }
    return null;
  }

  /**
   * Get tenant-specific rate limit profile
   */
  async getTenantRateLimitProfile(tenantId: string): Promise<TenantRateLimitProfile | null> {
    // First check cache
    const cached = await this.redis.get(`${this.cachePrefix}${tenantId}`);
    if (cached) {
      return JSON.parse(cached);
    }

    // Get from database
    const profile = await this.prisma.tenantRateLimitProfile.findFirst({
      where: { tenantId, isActive: true },
    });

    if (profile) {
        const typedProfile: TenantRateLimitProfile = {
            id: profile.id,
            tenantId: profile.tenantId,
            name: profile.name,
            limits: profile.limits as any, // Cast JSON to expected structure
            createdAt: profile.createdAt,
            updatedAt: profile.updatedAt,
            isActive: profile.isActive,
          };

      // Cache for 10 minutes
      await this.redis.setex(`${this.cachePrefix}${tenantId}`, 600, JSON.stringify(typedProfile));
      return typedProfile;
    }

    return null;
  }

  /**
   * Create or update tenant rate limit profile
   */
  async createOrUpdateTenantProfile(
    tenantId: string,
    profileData: Omit<TenantRateLimitProfile, 'id' | 'tenantId' | 'createdAt' | 'updatedAt'>
  ): Promise<TenantRateLimitProfile> {
    const existing = await this.prisma.tenantRateLimitProfile.findFirst({
      where: { tenantId },
    });

    let profile;

    if (existing) {
      profile = await this.prisma.tenantRateLimitProfile.update({
        where: { id: existing.id },
        data: {
          name: profileData.name,
          limits: profileData.limits as any, // Cast to Json for Prisma
          isActive: profileData.isActive ?? true,
          updatedAt: new Date(),
        },
      });
    } else {
      profile = await this.prisma.tenantRateLimitProfile.create({
        data: {
          name: profileData.name,
          limits: profileData.limits as any, // Cast to Json for Prisma
          isActive: profileData.isActive ?? true,
          tenantId,
          id: `rate-profile-${crypto.randomUUID()}`,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      });
    }

    // Cast the Prisma result to your application type
    const typedProfile: TenantRateLimitProfile = {
      id: profile.id,
      tenantId: profile.tenantId,
      name: profile.name,
      limits: profile.limits as any, // Cast back to expected structure
      createdAt: profile.createdAt,
      updatedAt: profile.updatedAt,
      isActive: profile.isActive,
    };

    // Update cache
    await this.redis.setex(`${this.cachePrefix}${tenantId}`, 600, JSON.stringify(typedProfile));

    // Log the change
    await this.eventLog.logEvent('USER_PROFILE_UPDATE', {
      userId: null, // System operation
      tenantId,
      metadata: {
        action: 'RATE_LIMIT_PROFILE_UPDATED',
        profileId: typedProfile.id,
        profileName: typedProfile.name,
      },
      ipAddress: null,
      userAgent: null,
      severity: 'SECURITY',
    });

    return typedProfile;
  }

  /**
   * Get rate limit usage statistics for a tenant
   */
  async getRateLimitUsage(tenantId: string, endpoint?: string): Promise<RateLimitUsage[]> {
    // This would query Redis for current usage data
    // For now, return empty array - implementation would depend on your specific needs
    return [];
  }

  /**
   * Get all tenant rate limit profiles
   */
  async getAllTenantProfiles(): Promise<TenantRateLimitProfile[]> {
    const profiles = await this.prisma.tenantRateLimitProfile.findMany({
      where: { isActive: true },
      orderBy: { createdAt: 'desc' },
    });

    // Convert Prisma results to application types
    return profiles.map(profile => ({
      id: profile.id,
      tenantId: profile.tenantId,
      name: profile.name,
      limits: profile.limits as any, // Cast JSON to expected structure
      createdAt: profile.createdAt,
      updatedAt: profile.updatedAt,
      isActive: profile.isActive,
    }));
  }

  /**
   * Fixed window rate limiting (e.g., 100 requests per hour)
   */
  private async checkFixedWindowRateLimit(
    key: string,
    config: RateLimitConfig
  ): Promise<{ allowed: boolean; remaining: number; resetTime: Date; retryAfter?: number }> {
    const windowKey = `${key}:fixed`;
    const countKey = `${windowKey}:count`;
    const startKey = `${windowKey}:start`;

    const now = Date.now();
    const windowStart = await this.redis.get(startKey);
    let count = 0;

    if (windowStart && now - parseInt(windowStart) < config.windowMs) {
      // Window is still active, get current count
      const currentCount = await this.redis.get(countKey);
      count = currentCount ? parseInt(currentCount) : 0;
    } else {
      // Window expired or doesn't exist, reset
      await this.redis.setex(startKey, Math.ceil(config.windowMs / 1000), now.toString());
      await this.redis.setex(countKey, Math.ceil(config.windowMs / 1000), '1');
      return { allowed: true, remaining: config.limit - 1, resetTime: new Date(now + config.windowMs) };
    }

    if (count >= config.limit) {
      // Rate limit exceeded
      const resetTime = new Date(parseInt(windowStart) + config.windowMs);
      const retryAfter = Math.ceil((resetTime.getTime() - now) / 1000);
      
      // Increment count anyway to track over-limit requests
      await this.redis.incr(countKey);
      
      return { 
        allowed: false, 
        remaining: 0, 
        resetTime, 
        retryAfter 
      };
    }

    // Increment count
    await this.redis.incr(countKey);
    const newCount = count + 1;
    
    return { 
      allowed: true, 
      remaining: config.limit - newCount, 
      resetTime: new Date(parseInt(windowStart) + config.windowMs) 
    };
  }

  /**
   * Sliding window rate limiting (more accurate)
   */
  private async checkSlidingWindowRateLimit(
    key: string,
    config: RateLimitConfig
  ): Promise<{ allowed: boolean; remaining: number; resetTime: Date; retryAfter?: number }> {
    const windowKey = `${key}:sliding`;
    const now = Date.now();
    const windowStart = now - config.windowMs;

    // Get timestamps within current window
    const timestamps = await this.redis.lrange(windowKey, 0, -1);
    const validTimestamps = timestamps.filter(ts => parseInt(ts) >= windowStart);

    if (validTimestamps.length >= config.limit) {
      // Rate limit exceeded
      const oldest = Math.min(...validTimestamps.map(ts => parseInt(ts)));
      const resetTime = new Date(oldest + config.windowMs);
      const retryAfter = Math.ceil((resetTime.getTime() - now) / 1000);
      
      // Add current request timestamp
      await this.redis.lpush(windowKey, now.toString());
      await this.redis.ltrim(windowKey, 0, config.limit - 1); // Keep only last N requests
      await this.redis.expire(windowKey, Math.ceil(config.windowMs / 1000));
      
      return { 
        allowed: false, 
        remaining: 0, 
        resetTime, 
        retryAfter 
      };
    }

    // Add current request timestamp
    await this.redis.lpush(windowKey, now.toString());
    await this.redis.ltrim(windowKey, 0, config.limit - 1); // Keep only last N requests
    await this.redis.expire(windowKey, Math.ceil(config.windowMs / 1000));

    return { 
      allowed: true, 
      remaining: config.limit - validTimestamps.length - 1, 
      resetTime: new Date(now + config.windowMs) 
    };
  }

  /**
   * Token bucket rate limiting
   */
  private async checkTokenBucketRateLimit(
    key: string,
    config: RateLimitConfig
  ): Promise<{ allowed: boolean; remaining: number; resetTime: Date; retryAfter?: number }> {
    const bucketKey = `${key}:bucket`;
    const lastRefillKey = `${bucketKey}:lastRefill`;
    const tokensKey = `${bucketKey}:tokens`;

    const now = Date.now();
    const refillInterval = config.windowMs / config.limit; // Time between tokens
    const maxTokens = config.limit;

    // Get current state
    let lastRefill = await this.redis.get(lastRefillKey);
    let tokens = await this.redis.get(tokensKey);

    console.log('DEBUG - Token Bucket:', {
      lastRefill,
      tokens,
      now,
      config,
      maxTokens
    });

    if (!lastRefill) {
      // Initialize bucket
      lastRefill = now.toString();
      tokens = maxTokens.toString();
      await this.redis.setex(lastRefillKey, Math.ceil(config.windowMs / 1000), lastRefill);
      await this.redis.setex(tokensKey, Math.ceil(config.windowMs / 1000), tokens);

      console.log('DEBUG - Initialized bucket:', { lastRefill, tokens });
    }

    const lastRefillTime = parseInt(lastRefill || now.toString());
    const currentTokens = parseInt(tokens || maxTokens.toString()); 
    const timePassed = now - lastRefillTime;

    console.log('DEBUG - Before refill calculation:', {
      lastRefillTime,
      currentTokens,
      timePassed,
      refillInterval
    });

    // Refill tokens based on time passed
    const tokensToAdd = Math.floor(timePassed / refillInterval);
    let newTokens = Math.min(maxTokens, currentTokens + tokensToAdd);
    const nextRefill = lastRefillTime + (maxTokens - newTokens) * refillInterval;

    console.log('DEBUG - After refill calculation:', {
      tokensToAdd,
      newTokens,
      nextRefill
    });

    if (newTokens <= 0) {
      // No tokens available
      const resetTime = new Date(nextRefill);
      const retryAfter = Math.ceil((resetTime.getTime() - now) / 1000);
      
      console.log('DEBUG - No tokens available:', { resetTime, retryAfter });

      return { 
        allowed: false, 
        remaining: 0, 
        resetTime, 
        retryAfter 
      };
    }

    // Consume a token
    console.log('DEBUG - Before consuming token:', { newTokens });
  newTokens--;
  console.log('DEBUG - After consuming token:', { newTokens });

    await this.redis.setex(lastRefillKey, Math.ceil(config.windowMs / 1000), now.toString());
    await this.redis.setex(tokensKey, Math.ceil(config.windowMs / 1000), newTokens.toString());

    console.log('DEBUG - Final result:', { 
      allowed: true, 
      remaining: newTokens, 
      resetTime: new Date(nextRefill) 
    });

    return { 
      allowed: true, 
      remaining: newTokens, 
      resetTime: new Date(nextRefill) 
    };
  }

  /**
   * Generate unique rate limit key for a request
   */
  private generateRateLimitKey(tenantId: string, endpoint: string, ipAddress: string, userId?: string): string {
    const baseKey = `${tenantId}:${endpoint}`;
    const identifier = userId ? `${ipAddress}:${userId}` : ipAddress;
    return `${this.cachePrefix}${baseKey}:${identifier}`;
  }

  /**
   * Get rate limit config for an endpoint from profile
   */
  private getRateLimitConfig(profile: TenantRateLimitProfile, endpoint: string): RateLimitConfig | undefined {
    // Map endpoint to rate limit type
    const endpointMap: Record<string, keyof TenantRateLimitProfile['limits']> = {
      '/auth/otp/request': 'otpRequest',
      '/auth/otp/verify': 'otpVerify',
      '/auth/refresh': 'refresh',
      '/auth/login': 'login',
      '/api/': 'apiRequests', // General API endpoint
      '/upload/': 'fileUploads', // General upload endpoint
    };

    // Check for exact match first
    if (endpointMap[endpoint]) {
      return profile.limits[endpointMap[endpoint]];
    }

    // Check for partial matches (e.g., any /api/ endpoint)
    for (const [pattern, limitType] of Object.entries(endpointMap)) {
      if (endpoint.startsWith(pattern) && pattern !== '/api/' && pattern !== '/upload/') {
        return profile.limits[limitType];
      }
    }

    // Check for API endpoints
    if (endpoint.startsWith('/api/')) {
      return profile.limits.apiRequests;
    }

    // Check for upload endpoints
    if (endpoint.startsWith('/upload/')) {
      return profile.limits.fileUploads;
    }

    return undefined;
  }

  /**
   * Ensure default rate limit profiles exist
   */
  private async ensureDefaultProfiles() {
    for (const defaultProfile of this.defaultProfiles) {
        
        // 1. ENSURE THE PARENT TENANT RECORD EXISTS FIRST
        // This logic assumes you have the necessary data for the tenant
        // If the tenant doesn't exist, create a minimal tenant record:
        let tenant = await this.prisma.tenant.findUnique({
            where: { id: defaultProfile.tenantId },
        });

        if (!tenant) {
            this.logger.log(`Tenant ${defaultProfile.tenantId} not found, creating a placeholder tenant.`);
            // Create a minimal parent tenant record first
            tenant = await this.prisma.tenant.create({
                data: {
                    id: defaultProfile.tenantId,
                    name: `Default Tenant for Profile ${defaultProfile.name}`,
                    slug: `Default Tenant for Profile ${defaultProfile.slug}`,
                    // Add any other required fields for your Tenant model
                },
            });
        }


        // 2. Now attempt to create the profile for the guaranteed-existing tenant
        const existing = await this.prisma.tenantRateLimitProfile.findFirst({
            where: { 
                tenantId: defaultProfile.tenantId,
                name: defaultProfile.name,
            },
        });

        if (!existing) {
            await this.prisma.tenantRateLimitProfile.create({
                data: {
                    id: `default-${defaultProfile.name}-${crypto.randomUUID()}`,
                    tenantId: tenant.id, // Use the now-guaranteed tenant ID
                    name: defaultProfile.name,
                    limits: defaultProfile.limits as any,
                    isActive: defaultProfile.isActive,
                    createdAt: new Date(),
                    updatedAt: new Date(),
                },
            });
            this.logger.log(`Created default rate limit profile: ${defaultProfile.name}`);
        }
    }
}
  /**
   * Warm up cache with existing profiles
   */
  private async warmupCache() {
    try {
      const profiles = await this.prisma.tenantRateLimitProfile.findMany({
        where: { isActive: true },
      });

      for (const profile of profiles) {
        await this.redis.setex(`${this.cachePrefix}${profile.tenantId}`, 600, JSON.stringify(profile));
      }

      this.logger.log(`Warmed up cache with ${profiles.length} rate limit profiles`);
    } catch (error) {
      this.logger.error('Failed to warm up rate limit cache:', error);
    }
  }
}