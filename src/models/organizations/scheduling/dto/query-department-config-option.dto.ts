import { IsOptional, IsBoolean, IsString, IsIn } from 'class-validator';
import { Type } from 'class-transformer';
import { CONFIG_CATEGORIES, type ConfigCategory } from './create-department-config-option.dto';

export class QueryDepartmentConfigOptionDto {
  @IsOptional()
  @IsString()
  @IsIn(CONFIG_CATEGORIES)
  category?: ConfigCategory;

  @IsOptional()
  @Type(() => Boolean)
  @IsBoolean()
  is_active?: boolean;
}
