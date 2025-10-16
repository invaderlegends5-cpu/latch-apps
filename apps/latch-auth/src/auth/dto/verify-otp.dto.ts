import { IsString, IsNotEmpty } from 'class-validator';

export class VerifyOtpDto {
  @IsString()
  @IsNotEmpty()
  phone!: string;

  @IsString()
  @IsNotEmpty()
  code!: string;

  @IsString()
  tenantSlug?: string;
}
