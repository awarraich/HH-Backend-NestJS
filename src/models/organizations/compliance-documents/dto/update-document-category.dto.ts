import { IsString, IsOptional, IsInt, IsBoolean, MaxLength, Min } from 'class-validator';

export class UpdateDocumentCategoryDto {
  @IsString()
  @IsOptional()
  @MaxLength(255)
  name?: string;

  @IsString()
  @IsOptional()
  description?: string;

  @IsString()
  @IsOptional()
  @MaxLength(50)
  icon?: string;

  @IsString()
  @IsOptional()
  @MaxLength(20)
  color?: string;

  @IsInt()
  @IsOptional()
  @Min(0)
  sort_order?: number;

  @IsBoolean()
  @IsOptional()
  is_active?: boolean;
}
