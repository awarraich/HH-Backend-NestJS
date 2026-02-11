import { IsString, IsOptional, IsDateString, MaxLength } from 'class-validator';

export class CreatePatientForReferralDto {
  @IsString()
  @MaxLength(255)
  name: string;

  @IsOptional()
  @IsDateString()
  date_of_birth?: string;

  @IsOptional()
  @IsString()
  @MaxLength(500)
  address?: string;

  @IsOptional()
  @IsString()
  @MaxLength(200)
  primary_insurance_provider?: string;
}
