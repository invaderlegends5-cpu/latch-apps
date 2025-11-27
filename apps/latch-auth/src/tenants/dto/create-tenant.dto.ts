//src/tenants/dto/create-tenant.dto.ts:
import { 
    IsString, 
    IsNotEmpty, 
    IsEnum, 
    IsOptional, 
    Matches,
    MaxLength,
    MinLength,
    IsUrl,
    IsObject,
    ValidateNested,
    IsBoolean,
    IsArray,
    ArrayMinSize,
    ArrayMaxSize,
    IsNumber,
    IsDateString
  } from 'class-validator';
  import { Type } from 'class-transformer';
  
  export enum TenantStatusEnum {
    ACTIVE = 'ACTIVE',
    SUSPENDED = 'SUSPENDED'
  }
  
  export enum PermissionConflictStrategy {
    DENY_WINS = 'DENY_WINS',
    ALLOW_WINS = 'ALLOW_WINS',
    CUSTOM = 'CUSTOM'
  }

  export enum AllowedFactor {
    SMS = 'SMS',
    TOTP = 'TOTP',
    EMAIL = 'EMAIL',
    HARDWARE_TOKEN = 'HARDWARE_TOKEN'
  }
  
  class TenantSecurityDto {
    @IsOptional()
    @IsBoolean()
    privilegedUserMFARequired?: boolean;
  
    @IsOptional()
    @IsBoolean()
    roleInheritanceEnabled?: boolean;
  
    @IsOptional()
    @IsEnum(PermissionConflictStrategy)
    permissionConflictStrategy?: PermissionConflictStrategy;
  
    @IsOptional()
    @IsArray()
    @ArrayMinSize(1)
    @ArrayMaxSize(10)
    @IsEnum(AllowedFactor, { each: true })
    allowedFactors?: AllowedFactor[];

    @IsOptional()
    @IsBoolean()
    enforcePasswordComplexity?: boolean;
  
    @IsOptional()
    @IsBoolean()
    requireMFA?: boolean;
  
    @IsOptional()
    @IsNumber()
    passwordMinLength?: number;
  
    @IsOptional()
    @IsDateString()
    passwordExpiryDate?: string;
  
    @IsOptional()
    @IsNumber()
    maxFailedLoginAttempts?: number;
  
    @IsOptional()
    @IsNumber()
    lockoutDurationSeconds?: number;
  }

  class TenantBrandingDto {
    @IsOptional()
    @IsString()
    @MaxLength(100)
    logoUrl?: string;
  
    @IsOptional()
    @IsString()
    @MaxLength(100)
    primaryColor?: string;
  
    @IsOptional()
    @IsString()
    @MaxLength(100)
    secondaryColor?: string;
  
    @IsOptional()
    @IsString()
    @MaxLength(100)
    companyName?: string;
  }
  
  export class CreateTenantDto {
    @IsString({ message: 'Tenant name must be a string' })
    @IsNotEmpty({ message: 'Tenant name is required' })
    @MinLength(2, { message: 'Tenant name must be at least 2 characters long' })
    @MaxLength(100, { message: 'Tenant name cannot exceed 100 characters' })
    @Matches(/^[a-zA-Z0-9\s\-_.,&()]+$/, { 
      message: 'Tenant name contains invalid characters' 
    })
    name: string;
    
    @IsString({ message: 'Tenant slug must be a string' })
    @IsNotEmpty({ message: 'Tenant slug is required' })
    @MinLength(2, { message: 'Tenant slug must be at least 2 characters long' })
    @MaxLength(50, { message: 'Tenant slug cannot exceed 50 characters' })
    @Matches(/^[a-z0-9][a-z0-9\-_]*[a-z0-9]$/, { 
      message: 'Tenant slug must start and end with alphanumeric characters, and only contain lowercase letters, numbers, hyphens, and underscores' 
    })
    slug: string;
  
    @IsEnum(TenantStatusEnum, { 
      message: 'Status must be either ACTIVE or SUSPENDED' 
    })
    @IsOptional()
    status?: TenantStatusEnum = TenantStatusEnum.ACTIVE;
  
    @IsOptional()
    @ValidateNested()
    @Type(() => TenantBrandingDto)
    branding?: TenantBrandingDto;
  
    @IsOptional()
    @IsBoolean()
    requireMFA?: boolean = false;
  
    @IsOptional()
    @IsString()
    @MaxLength(200)
    defaultRoleName?: string;

    @IsOptional()
    @ValidateNested()
    @Type(() => TenantSecurityDto)
    security?: TenantSecurityDto;
  }