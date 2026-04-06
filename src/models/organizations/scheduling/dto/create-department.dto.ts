import {
  IsString,
  IsNotEmpty,
  IsOptional,
  IsBoolean,
  IsInt,
  IsArray,
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

/** Station item for inline creation within a department. */
export class InlineStationDto {
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

export class CreateDepartmentDto {
  @IsNotEmpty()
  @IsString()
  @MaxLength(255)
  name: string;

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
}
