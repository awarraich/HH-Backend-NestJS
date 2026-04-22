import {
  IsString,
  IsNotEmpty,
  IsOptional,
  IsBoolean,
  IsInt,
  IsArray,
  IsObject,
  IsUUID,
  ValidateNested,
  MaxLength,
  Min,
} from 'class-validator';
import { Type } from 'class-transformer';

/** Room item for inline creation within a station (nested in department). */
export class InlineStationRoomDto {
  @IsNotEmpty()
  @IsString()
  @MaxLength(100)
  name: string;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  beds?: number;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  chairs?: number;
}

/** Station item for inline creation OR update within a department.
 *
 * Update semantics match InlineShiftDto: supply `id` for an existing
 * station (row is preserved, rooms/beds/chairs/station_shift_assignments
 * are merged rather than replaced). Omit `id` for a new station.
 */
export class InlineStationDto {
  @IsOptional()
  @IsUUID()
  id?: string;

  @IsNotEmpty()
  @IsString()
  @MaxLength(255)
  name: string;

  @IsOptional()
  @IsString()
  @MaxLength(255)
  location?: string;

  @IsOptional()
  @Type(() => Boolean)
  @IsBoolean()
  multi_station_am?: boolean;

  @IsOptional()
  @Type(() => Boolean)
  @IsBoolean()
  multi_station_pm?: boolean;

  @IsOptional()
  @Type(() => Boolean)
  @IsBoolean()
  multi_station_noc?: boolean;

  @IsOptional()
  custom_shift_times?: Record<string, { start: string; end: string }>;

  @IsOptional()
  @IsString()
  @MaxLength(20)
  configuration_type?: string;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  default_beds_per_room?: number;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  default_chairs_per_room?: number;

  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => InlineStationRoomDto)
  rooms?: InlineStationRoomDto[];

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  shift_ids?: string[];
}

/** Room item for inline creation directly under a department (rooms-only layout). */
export class InlineDepartmentRoomDto {
  @IsNotEmpty()
  @IsString()
  @MaxLength(100)
  name: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  room_type?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  floor?: string;

  @IsOptional()
  @IsString()
  @MaxLength(255)
  wing?: string;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  beds?: number;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  chairs?: number;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  shift_ids?: string[];
}

/** Shift for inline creation OR update within a department.
 *
 * Update semantics: if `id` is a real shift UUID, the update path treats
 * this entry as "modify existing" and preserves the row (and every
 * downstream relationship — employee_shifts, station_shift_assignments,
 * etc.). Omit `id` for genuinely new shifts; the backend creates them and
 * maps `temp_id` to the generated UUID for cross-references inside the
 * same payload. See DepartmentService.update for the diff logic.
 */
export class InlineShiftDto {
  @IsOptional()
  @IsUUID()
  id?: string;

  @IsNotEmpty()
  @IsString()
  temp_id: string;

  @IsNotEmpty()
  @IsString()
  @MaxLength(255)
  name: string;

  @IsNotEmpty()
  @IsString()
  start_time: string;

  @IsNotEmpty()
  @IsString()
  end_time: string;

  @IsOptional()
  @IsString()
  recurrence?: string;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  custom_days?: string[];

  @IsOptional()
  @IsString()
  duration?: string;

  @IsOptional()
  @IsString()
  duration_start_date?: string;

  @IsOptional()
  @IsString()
  duration_end_date?: string;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  assigned_roles?: string[];
}

/** Staff configuration for inline creation within a department. */
export class InlineStaffDto {
  /** UUID from provider_roles. Preferred over the free-text `type` code. */
  @IsOptional()
  @IsUUID()
  provider_role_id?: string;

  @IsNotEmpty()
  @IsString()
  @MaxLength(50)
  type: string;

  @IsNotEmpty()
  @IsString()
  @MaxLength(100)
  name: string;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  quantity?: number;

  @IsOptional()
  @IsObject()
  staff_by_shift?: Record<string, number>;

  @IsOptional()
  @IsObject()
  staff_min_max_by_shift?: Record<string, { min?: number; max?: number }>;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  assignment_level?: string;

  @IsOptional()
  @IsString()
  @MaxLength(20)
  assignment_type?: string;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  shift_ids?: string[];
}

/** Zone for inline creation within a department (field layout). */
export class InlineZoneDto {
  @IsNotEmpty()
  @IsString()
  @MaxLength(255)
  name: string;

  @IsOptional()
  @IsString()
  @MaxLength(255)
  area?: string;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  patient_count?: number;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  shift_ids?: string[];
}

/** Fleet vehicle for inline creation within a department (fleet layout). */
export class InlineFleetVehicleDto {
  @IsNotEmpty()
  @IsString()
  @MaxLength(255)
  name: string;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  vehicle_id?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  vehicle_type?: string;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  capacity?: number;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  shift_ids?: string[];
}

/** Lab workstation for inline creation within a department (lab layout). */
export class InlineLabWorkstationDto {
  @IsNotEmpty()
  @IsString()
  @MaxLength(255)
  name: string;

  @IsOptional()
  @IsString()
  equipment?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  workstation_type?: string;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  shift_ids?: string[];
}

export class CreateDepartmentDto {
  @IsNotEmpty()
  @IsString()
  @MaxLength(255)
  name: string;

  /** IANA timezone of the client (e.g. "America/Los_Angeles"). Used to
   *  convert inline shift start/end times from local to UTC before storage. */
  @IsOptional()
  @IsString()
  @MaxLength(50)
  timezone?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  code?: string;

  @IsOptional()
  @IsString()
  description?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  department_type?: string;

  @IsOptional()
  @IsString()
  @MaxLength(30)
  layout_type?: string;

  @IsOptional()
  @IsString()
  @MaxLength(255)
  department_head?: string;

  @IsOptional()
  @Type(() => Boolean)
  @IsBoolean()
  allow_multi_station_coverage?: boolean;

  @IsOptional()
  @Type(() => Boolean)
  @IsBoolean()
  is_active?: boolean;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  sort_order?: number;

  /** Nested stations for bulk creation (layout_type='stations'). */
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => InlineStationDto)
  stations?: InlineStationDto[];

  /** Direct rooms for bulk creation (layout_type='rooms'). */
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => InlineDepartmentRoomDto)
  rooms?: InlineDepartmentRoomDto[];

  /** Department shift library. */
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => InlineShiftDto)
  available_shifts?: InlineShiftDto[];

  /** Staff configuration. */
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => InlineStaffDto)
  staff?: InlineStaffDto[];

  /** Field zones (layout_type='field'). */
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => InlineZoneDto)
  field_zones?: InlineZoneDto[];

  /** Fleet vehicles (layout_type='fleet'). */
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => InlineFleetVehicleDto)
  fleet_vehicles?: InlineFleetVehicleDto[];

  /** Lab workstations (layout_type='lab'). */
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => InlineLabWorkstationDto)
  lab_workstations?: InlineLabWorkstationDto[];
}
