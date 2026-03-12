import {
  IsString,
  IsOptional,
  IsIn,
  IsBoolean,
  IsNumber,
  IsArray,
  IsDateString,
  MaxLength,
} from 'class-validator';

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
}
