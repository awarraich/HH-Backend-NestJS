import {
  IsDateString,
  IsInt,
  IsOptional,
  IsString,
  MaxLength,
  Min,
} from 'class-validator';
import { Type } from 'class-transformer';
import {
  CreateScheduledTaskBase,
  UpdateScheduledTaskBase,
  QueryScheduledTaskBase,
} from './scheduled-task-base.dto';

export class ClinicAppointmentDetailsDto {
  @IsString()
  @MaxLength(128)
  appointment_type: string;

  @IsOptional()
  @IsString()
  @MaxLength(500)
  chief_complaint?: string;

  @IsOptional()
  @IsString()
  @MaxLength(128)
  insurance_provider?: string;

  @IsOptional()
  @IsDateString()
  patient_date_of_birth?: string;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  duration_minutes?: number;
}

// `details` is inherited from the base as `Record<string, unknown>`.
// `ClinicAppointmentDetailsDto` above documents the expected shape — it can be
// wired up with @ValidateNested() later without touching the controller surface.
export class CreateClinicAppointmentDto extends CreateScheduledTaskBase {}

export class UpdateClinicAppointmentDto extends UpdateScheduledTaskBase {}

export class QueryClinicAppointmentDto extends QueryScheduledTaskBase {
  @IsOptional()
  @IsString()
  appointment_type?: string;
}
