import { IsString, IsNotEmpty, IsOptional, IsInt, IsArray, IsObject, IsUUID, MaxLength, Min } from 'class-validator';
import { Type } from 'class-transformer';

export class CreateDepartmentStaffDto {
  @IsOptional()
  @IsUUID()
  provider_role_id?: string;

  @IsNotEmpty()
  @IsString()
  @MaxLength(50)
  staff_type: string;

  @IsNotEmpty()
  @IsString()
  @MaxLength(100)
  staff_name: string;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  quantity?: number;

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

  @IsOptional()
  @IsObject()
  staff_by_shift?: Record<string, number>;

  @IsOptional()
  @IsObject()
  staff_min_max_by_shift?: Record<string, { min?: number; max?: number }>;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  sort_order?: number;
}
