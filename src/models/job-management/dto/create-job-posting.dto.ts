import {
  IsString,
  IsOptional,
  IsIn,
  IsBoolean,
  IsNumber,
  IsArray,
  IsDateString,
  MaxLength,
  ValidateNested,
  ArrayMaxSize,
} from 'class-validator';
import { Type } from 'class-transformer';

export class ApplicationFieldSnapshotDto {
  @IsString()
  @MaxLength(128)
  id!: string;

  @IsString()
  @MaxLength(255)
  label!: string;

  @IsString()
  @MaxLength(64)
  type!: string;

  @IsBoolean()
  required!: boolean;

  @IsOptional()
  @IsString()
  @MaxLength(255)
  placeholder?: string;

  @IsOptional()
  @IsArray()
  @ArrayMaxSize(200)
  @IsString({ each: true })
  options?: string[];
}

export class CreateJobPostingDto {
  @IsString()
  @MaxLength(500)
  title: string;

  @IsOptional()
  @IsString()
  description?: string;

  @IsOptional()
  @IsString()
  @MaxLength(255)
  location?: string;

  @IsOptional()
  @IsString()
  @IsIn(['in_person', 'remote', 'hybrid'])
  location_type?: string;

  @IsOptional()
  @IsString()
  @MaxLength(255)
  salary_range?: string;

  @IsOptional()
  @IsDateString()
  application_deadline?: string;

  @IsOptional()
  @IsString()
  @IsIn(['active', 'closed', 'filled'])
  status?: string;

  @IsOptional()
  expand_candidate_search?: boolean;

  @IsOptional()
  @IsArray()
  required_fields?: unknown[];

  @IsOptional()
  @IsArray()
  optional_fields?: unknown[];

  @IsOptional()
  @IsArray()
  job_types?: string[];

  @IsOptional()
  @IsString()
  expected_hours_type?: string;

  @IsOptional()
  @IsString()
  expected_hours_value?: string;

  @IsOptional()
  @IsString()
  pay_type?: string;

  @IsOptional()
  @IsString()
  pay_minimum?: string;

  @IsOptional()
  @IsString()
  pay_maximum?: string;

  @IsOptional()
  @IsString()
  pay_rate?: string;

  @IsOptional()
  @IsArray()
  benefits?: string[];

  @IsOptional()
  @IsArray()
  education_level?: string[];

  @IsOptional()
  @IsArray()
  licenses_certifications?: string[];

  @IsOptional()
  @IsArray()
  field_of_study?: string[];

  @IsOptional()
  @IsArray()
  experience?: string[];

  @IsOptional()
  @IsArray()
  required_qualifications?: string[];

  @IsOptional()
  @IsArray()
  preferred_qualifications?: string[];

  @IsOptional()
  @IsArray()
  skills?: string[];

  @IsOptional()
  @IsArray()
  communication_emails?: string[];

  @IsOptional()
  @IsBoolean()
  send_individual_emails?: boolean;

  @IsOptional()
  @IsBoolean()
  resume_required?: boolean;

  @IsOptional()
  @IsBoolean()
  allow_candidate_contact?: boolean;

  @IsOptional()
  @IsBoolean()
  criminal_record_encouraged?: boolean;

  @IsOptional()
  @IsBoolean()
  background_check_required?: boolean;

  @IsOptional()
  @IsString()
  hiring_timeline?: string;

  @IsOptional()
  @IsNumber()
  people_to_hire?: number;

  /** Job-specific application form fields. When set, applicants see this form instead of org default. */
  @IsOptional()
  @IsArray()
  application_fields?: Array<{
    id?: string;
    label: string;
    type: string;
    required?: boolean;
    placeholder?: string;
    options?: string[];
  }>;

  /**
   * Per-job snapshot of the full application form field definitions.
   *
   * When provided, this becomes the source of truth for applicants on THIS
   * posting and the org setup is no longer consulted. Editing the org setup
   * later does not retroactively mutate existing postings.
   *
   * Capped at 200 fields per posting.
   */
  @IsOptional()
  @IsArray()
  @ArrayMaxSize(200)
  @ValidateNested({ each: true })
  @Type(() => ApplicationFieldSnapshotDto)
  application_fields_snapshot?: ApplicationFieldSnapshotDto[];
}
