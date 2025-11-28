import { ConditionType } from '../../events/event.types';

export interface TenantRateLimitProfile {
    id: string;
    tenantId: string;
    name: string; // e.g., 'standard', 'premium', 'enterprise'
    slug?: string;
    limits: {
      otpRequest: RateLimitConfig;
      otpVerify: RateLimitConfig;
      refresh: RateLimitConfig;
      login: RateLimitConfig;
      apiRequests: RateLimitConfig;
      fileUploads: RateLimitConfig;
      // Add more as needed
    };
    createdAt: Date;
    updatedAt: Date;
    isActive: boolean;
  }
  
  export interface RateLimitConfig {
    limit: number; // Number of requests
    windowMs: number; // Time window in milliseconds
    type: 'fixed' | 'sliding' | 'token-bucket'; // Rate limiting algorithm
    burstAllowance?: number; // Additional requests allowed in burst scenarios
    penalty?: RateLimitPenalty; // Penalty for exceeding limits
  }
  
  export interface RateLimitPenalty {
    type: 'block' | 'delay' | 'captcha';
    durationMs?: number; // For 'block' or 'delay'
    multiplier?: number; // For 'delay' (e.g., 2x means double the delay)
  }
  
  export interface RateLimitUsage {
    tenantId: string;
    endpoint: string;
    windowStart: Date;
    count: number;
    resetTime: Date;
    remaining: number;
  }
  

  export interface RateLimitCondition {
    conditionType: ConditionType; // Use literal string type
    value: {
      endpoint: string;
      limit: number;
      windowMs: number;
      algorithm: 'fixed' | 'sliding' | 'token-bucket';
    };
    description?: string;
  }