import {
  IsString,
  IsOptional,
  IsInt,
  IsIn,
  IsDateString,
  MaxLength,
  Min,
  Max,
} from 'class-validator';

export class UpdateEmployeeProfileDto {
  @IsOptional()
  @IsString()
  @MaxLength(255)
  name?: string;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  profile_image?: string;

  @IsOptional()
  @IsString()
  @MaxLength(255)
  address_line_1?: string;

  @IsOptional()
  @IsString()
  @MaxLength(255)
  address_line_2?: string;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  city?: string;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  state?: string;

  @IsOptional()
  @IsString()
  @MaxLength(20)
  phone_number?: string;

  @IsOptional()
  @IsString()
  @IsIn(['MALE', 'FEMALE', 'OTHER', 'PREFER_NOT_TO_SAY'])
  @MaxLength(20)
  gender?: string;

  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(150)
  age?: number;

  @IsOptional()
  emergency_contact?: Record<string, unknown>;

  @IsOptional()
  @IsDateString()
  date_of_birth?: string;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  specialization?: string;

  @IsOptional()
  @IsInt()
  @Min(0)
  @Max(100)
  years_of_experience?: number;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  certification?: string;

  @IsOptional()
  board_certifications?: Record<string, unknown>;

  // Onboarding-completion timestamps set by the first-login wizard. All
  // four are optional ISO date strings — the wizard sends them on Finish,
  // and HR-side edits never touch them. We accept them through the same
  // DTO so a single PUT covers the whole profile flow.
  @IsOptional()
  @IsDateString()
  portal_wizard_completed_at?: string;

  @IsOptional()
  @IsDateString()
  hipaa_acknowledged_at?: string;

  @IsOptional()
  @IsDateString()
  background_check_acknowledged_at?: string;

  @IsOptional()
  @IsDateString()
  i9_acknowledged_at?: string;
}
