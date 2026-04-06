import {
  IsString,
  IsNotEmpty,
  IsOptional,
  IsBoolean,
  IsInt,
  IsIn,
  MaxLength,
  Min,
} from 'class-validator';
import { Type } from 'class-transformer';

export const CONFIG_CATEGORIES = [
  'DEPARTMENT_TYPE',
  'ROOM_TYPE',
  'LAYOUT_TYPE',
  'CONFIGURATION_TYPE',
] as const;

export type ConfigCategory = (typeof CONFIG_CATEGORIES)[number];

export class CreateDepartmentConfigOptionDto {
  @IsNotEmpty()
  @IsString()
  @IsIn(CONFIG_CATEGORIES)
  category: ConfigCategory;

  @IsNotEmpty()
  @IsString()
  @MaxLength(50)
  value: string;

  @IsNotEmpty()
  @IsString()
  @MaxLength(100)
  label: string;

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
  is_default?: boolean;

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
