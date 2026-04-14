import {
  IsString,
  IsOptional,
  IsBoolean,
  IsInt,
  IsIn,
  MaxLength,
  Min,
} from 'class-validator';
import { Type } from 'class-transformer';
import { CONFIG_CATEGORIES, type ConfigCategory } from './create-department-config-option.dto';

export class UpdateDepartmentConfigOptionDto {
  @IsOptional()
  @IsString()
  @IsIn(CONFIG_CATEGORIES)
  category?: ConfigCategory;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  value?: string;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  label?: string;

  @IsOptional()
  @IsString()
  description?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  icon?: string;

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
