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
}
