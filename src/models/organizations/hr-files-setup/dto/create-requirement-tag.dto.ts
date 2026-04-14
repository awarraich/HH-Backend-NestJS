import { IsString, IsNotEmpty, IsOptional, IsArray, IsUUID, MaxLength } from 'class-validator';

export class CreateRequirementTagDto {
  @IsNotEmpty()
  @IsString()
  @MaxLength(255)
  title: string;

  @IsNotEmpty()
  @IsString()
  @MaxLength(100)
  category: string;

  @IsOptional()
  @IsArray()
  @IsUUID('4', { each: true })
  document_type_ids?: string[];

  @IsOptional()
  @IsArray()
  @IsUUID('4', { each: true })
  inservice_training_ids?: string[];

  @IsOptional()
  @IsArray()
  @IsUUID('4', { each: true })
  document_template_ids?: string[];
}
