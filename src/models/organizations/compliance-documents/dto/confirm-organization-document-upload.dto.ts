import {
  IsBoolean,
  IsDateString,
  IsInt,
  IsOptional,
  IsPositive,
  IsString,
  IsUUID,
  MaxLength,
} from 'class-validator';

export class ConfirmOrganizationDocumentUploadDto {
  @IsString()
  @MaxLength(1024)
  key!: string;

  @IsString()
  @MaxLength(255)
  file_name!: string;

  @IsString()
  @MaxLength(255)
  document_name!: string;

  @IsUUID()
  category_id!: string;

  @IsOptional()
  @IsBoolean()
  is_required?: boolean;

  @IsOptional()
  @IsBoolean()
  has_expiration?: boolean;

  @IsOptional()
  @IsDateString()
  expiration_date?: string;

  @IsOptional()
  @IsString()
  @MaxLength(127)
  mime_type?: string;

  @IsOptional()
  @IsInt()
  @IsPositive()
  size_bytes?: number;
}
