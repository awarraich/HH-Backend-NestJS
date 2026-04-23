import { IsString, IsOptional, IsBoolean, IsInt, IsArray, ValidateNested, MaxLength, Min } from 'class-validator';
import { Type } from 'class-transformer';
import {
  InlineStationDto,
  InlineDepartmentRoomDto,
  InlineShiftDto,
  InlineStaffDto,
  InlineZoneDto,
  InlineFleetVehicleDto,
  InlineLabWorkstationDto,
} from './create-department.dto';

export class UpdateDepartmentDto {
  @IsOptional()
  @IsString()
  @MaxLength(255)
  name?: string;

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

  /** Nested stations for bulk replace (layout_type='stations'). */
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => InlineStationDto)
  stations?: InlineStationDto[];

  /** Direct rooms for bulk replace (layout_type='rooms'). */
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => InlineDepartmentRoomDto)
  rooms?: InlineDepartmentRoomDto[];

  /** Department shift library (replaces all shifts). */
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => InlineShiftDto)
  available_shifts?: InlineShiftDto[];

  /** Staff configuration (replaces all staff). */
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
