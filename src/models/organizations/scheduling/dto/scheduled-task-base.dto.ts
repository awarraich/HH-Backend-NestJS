import {
  IsDateString,
  IsInt,
  IsOptional,
  IsString,
  IsUUID,
  Max,
  MaxLength,
  Min,
} from 'class-validator';
import { Type } from 'class-transformer';

/**
 * Canonical input for creating a scheduled task. Per-view controllers
 * transform their view-specific DTOs into this shape before calling the
 * service, so the service layer stays task-type agnostic.
 */
export class CreateScheduledTaskBase {
  @IsDateString()
  scheduled_start_at: string;

  @IsDateString()
  scheduled_end_at: string;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  @Max(3)
  priority?: number;

  @IsOptional()
  @IsUUID('4')
  department_id?: string;

  @IsOptional()
  @IsUUID('4')
  station_id?: string;

  @IsOptional()
  @IsUUID('4')
  room_id?: string;

  @IsOptional()
  @IsUUID('4')
  bed_id?: string;

  @IsOptional()
  @IsUUID('4')
  chair_id?: string;

  @IsOptional()
  @IsUUID('4')
  zone_id?: string;

  @IsOptional()
  @IsUUID('4')
  fleet_vehicle_id?: string;

  @IsOptional()
  @IsUUID('4')
  lab_workstation_id?: string;

  @IsOptional()
  @IsUUID('4')
  shift_id?: string;

  @IsOptional()
  @IsString()
  @MaxLength(255)
  subject_name?: string;

  @IsOptional()
  @IsString()
  @MaxLength(64)
  subject_phone?: string;

  @IsOptional()
  @IsString()
  subject_address?: string;

  @IsOptional()
  @IsString()
  notes?: string;

  @IsOptional()
  details?: Record<string, unknown>;

  /**
   * Optional initial assignment — if provided, a primary assignment is
   * created atomically with the task. Additional assignments can be added
   * via the assignment endpoints.
   */
  @IsOptional()
  @IsUUID('4')
  primary_employee_id?: string;

  @IsOptional()
  @IsString()
  @MaxLength(64)
  primary_assignment_role?: string;
}

export class UpdateScheduledTaskBase {
  @IsOptional()
  @IsDateString()
  scheduled_start_at?: string;

  @IsOptional()
  @IsDateString()
  scheduled_end_at?: string;

  @IsOptional()
  @IsDateString()
  actual_start_at?: string;

  @IsOptional()
  @IsDateString()
  actual_end_at?: string;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  @Max(3)
  priority?: number;

  @IsOptional()
  @IsUUID('4')
  department_id?: string | null;

  @IsOptional()
  @IsUUID('4')
  station_id?: string | null;

  @IsOptional()
  @IsUUID('4')
  room_id?: string | null;

  @IsOptional()
  @IsUUID('4')
  bed_id?: string | null;

  @IsOptional()
  @IsUUID('4')
  chair_id?: string | null;

  @IsOptional()
  @IsUUID('4')
  zone_id?: string | null;

  @IsOptional()
  @IsUUID('4')
  fleet_vehicle_id?: string | null;

  @IsOptional()
  @IsUUID('4')
  lab_workstation_id?: string | null;

  @IsOptional()
  @IsUUID('4')
  shift_id?: string | null;

  @IsOptional()
  @IsString()
  @MaxLength(255)
  subject_name?: string;

  @IsOptional()
  @IsString()
  @MaxLength(64)
  subject_phone?: string;

  @IsOptional()
  @IsString()
  subject_address?: string;

  @IsOptional()
  @IsString()
  notes?: string;

  @IsOptional()
  details?: Record<string, unknown>;
}

export class QueryScheduledTaskBase {
  @IsOptional()
  @IsDateString()
  from_date?: string;

  @IsOptional()
  @IsDateString()
  to_date?: string;

  @IsOptional()
  @IsString()
  @MaxLength(32)
  status?: string;

  @IsOptional()
  @IsUUID('4')
  department_id?: string;

  @IsOptional()
  @IsUUID('4')
  station_id?: string;

  @IsOptional()
  @IsUUID('4')
  room_id?: string;

  @IsOptional()
  @IsUUID('4')
  zone_id?: string;

  @IsOptional()
  @IsUUID('4')
  fleet_vehicle_id?: string;

  @IsOptional()
  @IsUUID('4')
  assignee_employee_id?: string;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  page?: number = 1;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(500)
  limit?: number = 50;
}

export class TransitionScheduledTaskStatusDto {
  @IsString()
  @MaxLength(32)
  to_status: string;

  @IsOptional()
  @IsString()
  reason?: string;
}

export class CreateScheduledTaskAssignmentDto {
  @IsUUID('4')
  employee_id: string;

  @IsString()
  @MaxLength(64)
  assignment_role: string;

  @IsOptional()
  @IsUUID('4')
  employee_shift_id?: string;

  @IsOptional()
  is_primary?: boolean;
}
