import {
  IsString,
  IsNotEmpty,
  IsOptional,
  IsEmail,
  IsUUID,
  IsDateString,
  IsInt,
  Min,
  Max,
  MaxLength,
  IsIn,
  IsObject,
  IsArray,
} from 'class-validator';

export class CreateEmployeeByEmailDto {
  @IsNotEmpty()
  @IsEmail()
  email: string;

  @IsNotEmpty()
  @IsString()
  @MaxLength(255)
  firstName: string;

  @IsNotEmpty()
  @IsString()
  @MaxLength(255)
  lastName: string;

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
  @IsDateString()
  date_of_birth?: string;

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
  @IsUUID()
  provider_role_id?: string;

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
  @IsObject()
  board_certifications?: Record<string, unknown>;

  @IsOptional()
  @IsString()
  @IsIn(['FULL_TIME', 'PART_TIME', 'CONTRACT', 'PER_DIEM'])
  @MaxLength(20)
  employment_type?: string;

  @IsOptional()
  @IsString()
  @IsIn(['ACTIVE', 'INACTIVE', 'INVITED', 'TERMINATED'])
  @MaxLength(20)
  status?: string;

  @IsOptional()
  @IsDateString()
  start_date?: string;

  @IsOptional()
  @IsDateString()
  end_date?: string;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  department?: string;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  position_title?: string;

  @IsOptional()
  @IsString()
  notes?: string;

  /**
   * How the employee will sign in.
   * - TEMP_PASSWORD: Send email with temporary password (default).
   * - GOOGLE_SIGNIN: Send email instructing to sign in with Google.
   */
  @IsOptional()
  @IsString()
  @IsIn(['TEMP_PASSWORD', 'GOOGLE_SIGNIN'])
  authMethod?: 'TEMP_PASSWORD' | 'GOOGLE_SIGNIN';

  @IsOptional()
  @IsArray()
  @IsUUID('4', { each: true })
  requirement_tag_ids?: string[];
}
