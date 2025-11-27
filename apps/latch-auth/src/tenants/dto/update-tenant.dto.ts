//src/tenants/dto/update-tenant.dto.ts:
import { 
  IsString, 
  IsOptional, 
  IsEnum, 
  Matches,
  MaxLength,
  MinLength,
  IsObject,
  ValidateNested,
  IsBoolean,
  IsUrl,
  IsArray,
  IsIn,
  IsNumber,
  Min,
  Max,
  IsISO8601
} from 'class-validator';
import { Type } from 'class-transformer';
import { TenantStatusEnum } from './create-tenant.dto';

class UpdateTenantBrandingDto {
  @IsOptional()
  @IsUrl({ 
    require_protocol: true,
    protocols: ['https'] 
  }, { 
    message: 'Logo URL must be a valid HTTPS URL' 
  })
  @MaxLength(2048)
  logoUrl?: string;

  @IsOptional()
  @IsString()
  @Matches(/^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/, { 
    message: 'Primary color must be a valid hex color code (e.g., #FF0000)' 
  })
  @MaxLength(7)
  primaryColor?: string;

  @IsOptional()
  @IsString()
  @Matches(/^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/, { 
    message: 'Secondary color must be a valid hex color code (e.g., #FF0000)' 
  })
  @MaxLength(7)
  secondaryColor?: string;

  @IsOptional()
  @IsString()
  @MinLength(1)
  @MaxLength(100)
  @Matches(/^[a-zA-Z0-9\s\-_.,&()]+$/, { 
    message: 'Company name contains invalid characters' 
  })
  companyName?: string;
}

class UpdateTenantPolicyDto {
  @IsOptional()
  @IsBoolean()
  requireMFA?: boolean;

  @IsOptional()
  @IsBoolean()
  privilegedUserMFARequired?: boolean;

  @IsOptional()
  @IsBoolean()
  roleInheritanceEnabled?: boolean;

  @IsOptional()
  @IsIn(['DENY_WINS', 'ALLOW_WINS', 'HIGHEST_PRIORITY'], {
    message: 'Permission conflict strategy must be DENY_WINS, ALLOW_WINS, or HIGHEST_PRIORITY'
  })
  permissionConflictStrategy?: 'DENY_WINS' | 'ALLOW_WINS' | 'HIGHEST_PRIORITY';

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  @Max(10)
  allowedFactors?: string[];
}

class UpdateTenantSecurityDto {
  @IsOptional()
  @IsBoolean()
  enforcePasswordComplexity?: boolean;

  @IsOptional()
  @IsNumber({ maxDecimalPlaces: 0 })
  @Min(1)
  @Max(999)
  passwordMinLength?: number;

  @IsOptional()
  @IsISO8601()
  passwordExpiryDate?: string;

  @IsOptional()
  @IsNumber({ maxDecimalPlaces: 0 })
  @Min(1)
  @Max(100)
  maxFailedLoginAttempts?: number;

  @IsOptional()
  @IsNumber({ maxDecimalPlaces: 0 })
  @Min(60) // 1 minute minimum
  @Max(86400) // 24 hours maximum
  lockoutDurationSeconds?: number;
}

export class UpdateTenantDto {
  @IsOptional()
  @IsString({ message: 'Tenant name must be a string' })
  @MinLength(2, { message: 'Tenant name must be at least 2 characters long' })
  @MaxLength(100, { message: 'Tenant name cannot exceed 100 characters' })
  @Matches(/^[a-zA-Z0-9\s\-_.,&()]+$/, { 
    message: 'Tenant name contains invalid characters' 
  })
  name?: string;

  @IsOptional()
  @IsEnum(TenantStatusEnum, { 
    message: 'Status must be either ACTIVE or SUSPENDED' 
  })
  status?: TenantStatusEnum;

  @IsOptional()
  @ValidateNested()
  @Type(() => UpdateTenantBrandingDto)
  branding?: UpdateTenantBrandingDto;

  @IsOptional()
  @ValidateNested()
  @Type(() => UpdateTenantPolicyDto)
  policies?: UpdateTenantPolicyDto;

  @IsOptional()
  @ValidateNested()
  @Type(() => UpdateTenantSecurityDto)
  security?: UpdateTenantSecurityDto;

  @IsOptional()
  @IsBoolean()
  requireMFA?: boolean;

  @IsOptional()
  @IsString()
  @MaxLength(200)
  @Matches(/^[a-zA-Z0-9_\-]+$/, { 
    message: 'Default role name can only contain letters, numbers, hyphens, and underscores' 
  })
  defaultRoleName?: string;

  @IsOptional()
  @IsString()
  @MaxLength(500)
  @Matches(/^[a-zA-Z0-9\s\-_.,&()]+$/, { 
    message: 'Description contains invalid characters' 
  })
  description?: string;
}