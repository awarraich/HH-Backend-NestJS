import { IsString, IsOptional, IsBoolean, IsInt, MaxLength, Min } from 'class-validator';
import { Type } from 'class-transformer';

export class UpdateDepartmentDto {
  @IsOptional()
  @IsString()
  @MaxLength(255)
  name?: string;

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
}
