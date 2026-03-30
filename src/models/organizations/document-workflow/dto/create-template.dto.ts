import { IsString, IsIn, IsOptional, IsObject, IsArray } from 'class-validator';

export class CreateTemplateDto {
  @IsString()
  name: string;

  @IsOptional()
  @IsString()
  description?: string;

  @IsIn(['grid', 'document'])
  mode: 'grid' | 'document';

  @IsOptional()
  @IsObject()
  layout?: Record<string, any>;

  @IsOptional()
  @IsArray()
  documentFields?: Record<string, any>[];

  @IsOptional()
  @IsArray()
  roles?: Record<string, any>[];
}
