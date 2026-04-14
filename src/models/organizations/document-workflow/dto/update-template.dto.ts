import { IsString, IsOptional, IsArray } from 'class-validator';

export class UpdateTemplateDto {
  @IsOptional()
  @IsString()
  name?: string;

  @IsOptional()
  @IsString()
  description?: string;

  @IsOptional()
  @IsArray()
  documentFields?: Record<string, any>[];

  @IsOptional()
  @IsArray()
  roles?: Record<string, any>[];
}
