import {
  IsString,
  IsOptional,
  IsArray,
  IsUUID,
  MaxLength,
} from 'class-validator';

export class UpdateRequirementTagDto {
  @IsOptional()
  @IsString()
  @MaxLength(255)
  title?: string;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  category?: string;

  @IsOptional()
  @IsArray()
  @IsUUID('4', { each: true })
  document_type_ids?: string[];
}
