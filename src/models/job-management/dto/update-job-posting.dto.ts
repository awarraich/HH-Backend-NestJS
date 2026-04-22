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
import { ApplicationFieldSnapshotDto } from './create-job-posting.dto';

/** Full update: all fields optional so the edit form can send the same shape as create. */
export class UpdateJobPostingDto {
  @IsOptional()
  @IsString()
  @MaxLength(500)
  title?: string;

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
   * Per-job snapshot of the full application form field definitions. See the
   * same field on CreateJobPostingDto for the full contract.
   */
  @IsOptional()
  @IsArray()
  @ArrayMaxSize(200)
  @ValidateNested({ each: true })
  @Type(() => ApplicationFieldSnapshotDto)
  application_fields_snapshot?: ApplicationFieldSnapshotDto[];
}
