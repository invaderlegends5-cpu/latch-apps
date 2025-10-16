import { IsString, IsNotEmpty } from 'class-validator';

export class RequestOtpDto {
  @IsString()
  @IsNotEmpty()
  phone!: string;

  @IsString()
  tenantSlug?: string;
}
