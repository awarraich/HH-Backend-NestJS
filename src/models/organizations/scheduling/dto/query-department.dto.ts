import { IsOptional, IsBoolean, IsInt, IsString, MaxLength, Min, Max } from 'class-validator';
import { Type } from 'class-transformer';

export class QueryDepartmentDto {
  @IsOptional()
  @Type(() => Boolean)
  @IsBoolean()
  is_active?: boolean;

  /** Free-text filter applied to name/code/description (case-insensitive). */
  @IsOptional()
  @IsString()
  @MaxLength(255)
  search?: string;

  /** Filter by stored `department_type` (e.g. "NURSING", "CLINIC"). */
  @IsOptional()
  @IsString()
  @MaxLength(50)
  department_type?: string;

  /** Filter by `layout_type` (e.g. "stations", "rooms", "field"). */
  @IsOptional()
  @IsString()
  @MaxLength(30)
  layout_type?: string;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  page?: number = 1;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(100)
  limit?: number = 20;
}
