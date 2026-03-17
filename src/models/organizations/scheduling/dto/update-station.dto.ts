import { IsString, IsOptional, IsBoolean, IsInt, MaxLength, Min, Max } from 'class-validator';
import { Type } from 'class-transformer';

export class UpdateStationDto {
  @IsOptional()
  @IsString()
  @MaxLength(255)
  name?: string;

  @IsOptional()
  @IsString()
  @MaxLength(255)
  location?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  code?: string;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  @Max(20)
  required_charge_nurses?: number;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  @Max(50)
  required_cnas?: number;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  @Max(50)
  required_sitters?: number;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  @Max(50)
  required_treatment_nurses?: number;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  @Max(20)
  required_nps?: number;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  @Max(20)
  required_mds?: number;

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
  @IsString()
  @MaxLength(20)
  configuration_type?: string;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  @Max(10)
  default_beds_per_room?: number;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  @Max(10)
  default_chairs_per_room?: number;

  @IsOptional()
  custom_shift_times?: Record<string, { start: string; end: string }>;

  @IsOptional()
  @Type(() => Boolean)
  @IsBoolean()
  is_active?: boolean;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  sort_order?: number;
}
