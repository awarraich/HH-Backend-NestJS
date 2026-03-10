import { IsString, IsOptional, IsObject, MaxLength, ValidateIf } from 'class-validator';

export class CreateJobApplicationDto {
  @IsString()
  job_posting_id: string;

  @IsString()
  @MaxLength(255)
  applicant_name: string;

  @IsString()
  @MaxLength(255)
  applicant_email: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  applicant_phone?: string;

  @IsOptional()
  @IsString()
  notes?: string;

  @IsOptional()
  @ValidateIf((_o, v) => v != null && typeof v === 'object')
  @IsObject()
  submitted_fields?: Record<string, unknown>;
}
