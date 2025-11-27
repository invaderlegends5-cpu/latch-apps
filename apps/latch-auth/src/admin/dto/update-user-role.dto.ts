// src/admin/dto/update-user-role.dto.ts
import { 
    IsString, 
    IsNotEmpty, 
    IsUUID, 
    IsOptional, 
    IsBoolean, 
    ValidateNested,
    IsEnum,
    ArrayMinSize,
    ArrayMaxSize,
    IsArray,
    IsISO8601,
    IsNumber,
    Min,
    Max,
    MaxLength,
    IsIn,
    Matches,
    IsPositive,
  } from 'class-validator';
  import { Type } from 'class-transformer';
  
  export enum UserRoleOperation {
    ASSIGN = 'ASSIGN',
    REMOVE = 'REMOVE',
    REPLACE = 'REPLACE',
    INHERIT = 'INHERIT',
    TEMPORARY_ASSIGN = 'TEMPORARY_ASSIGN',
  }
  
  class UserRoleAssignment {
    @IsUUID()
    @IsNotEmpty()
    roleId: string;
  
    @IsOptional()
    @IsISO8601()
    validFrom?: string;
  
    @IsOptional()
    @IsISO8601()
    validUntil?: string;
  
    @IsOptional()
    @IsBoolean()
    isActive?: boolean;
  
    @IsOptional()
    @IsString()
    @IsNotEmpty()
    @MaxLength(500)
    @Matches(/^[a-zA-Z0-9\s\-_.,&():;!?#]+$/, { 
      message: 'Reason contains invalid characters' 
    })
    reason?: string;
  
    @IsOptional()
    @IsBoolean()
    notifyUser?: boolean;
  
    @IsOptional()
    @IsString()
    @IsNotEmpty()
    @MaxLength(100)
    @Matches(/^[a-zA-Z0-9_-]+$/, { 
      message: 'Context must contain only alphanumeric characters, hyphens, and underscores' 
    })
    context?: string;
  }
  
  export class UpdateUserRoleDto {
    @IsEnum(UserRoleOperation)
    operation: UserRoleOperation;
  
    @IsUUID()
    @IsNotEmpty()
    userId: string;
  
    @IsUUID()
    @IsNotEmpty()
    tenantId: string;
  
    @IsArray()
    @ValidateNested({ each: true })
    @Type(() => UserRoleAssignment)
    @ArrayMinSize(1)
    @ArrayMaxSize(20)
    roles: UserRoleAssignment[];
  
    @IsOptional()
    @IsString()
    @IsNotEmpty()
    @MaxLength(500)
    @Matches(/^[a-zA-Z0-9\s\-_.,&():;!?#]+$/, { 
      message: 'Reason contains invalid characters' 
    })
    reason?: string;
  
    @IsOptional()
    @IsBoolean()
    notifyUser?: boolean = false;
  
    @IsOptional()
    @IsString()
    @IsNotEmpty()
    @MaxLength(100)
    @Matches(/^[a-zA-Z0-9_-]+$/, { 
      message: 'Granted by must contain only alphanumeric characters, hyphens, and underscores' 
    })
    grantedBy?: string;
  
    @IsOptional()
    @IsString()
    @IsNotEmpty()
    @MaxLength(100)
    @Matches(/^[a-zA-Z0-9_-]+$/, { 
      message: 'Session context must contain only alphanumeric characters, hyphens, and underscores' 
    })
    sessionContext?: string;
  
    @IsOptional()
    @IsBoolean()
    bypassHierarchyCheck?: boolean;
  
    @IsOptional()
    @IsNumber()
    @Min(1)
    @Max(365)
    temporaryDurationDays?: number;
  
    @IsOptional()
    @IsString()
    @IsIn(['IMMEDIATE', 'NEXT_LOGIN', 'SCHEDULED'])
    activationStrategy?: string = 'IMMEDIATE';
  }