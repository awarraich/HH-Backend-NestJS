import { IsString, IsOptional, IsBoolean, IsInt, IsArray, MaxLength, Min } from 'class-validator';
import { Type } from 'class-transformer';

export class UpdateZoneDto {
  @IsOptional()
  @IsString()
  @MaxLength(255)
  name?: string;

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
  @Type(() => Boolean)
  @IsBoolean()
  is_active?: boolean;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  sort_order?: number;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  shift_ids?: string[];
}
