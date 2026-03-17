import { IsString, IsOptional, IsBoolean, IsUUID, IsDateString, MaxLength } from 'class-validator';

export class UpdateOrganizationDocumentDto {
  @IsString()
  @IsOptional()
  @MaxLength(255)
  document_name?: string;

  @IsUUID()
  @IsOptional()
  category_id?: string;

  @IsBoolean()
  @IsOptional()
  is_required?: boolean;

  @IsBoolean()
  @IsOptional()
  has_expiration?: boolean;

  @IsDateString()
  @IsOptional()
  expiration_date?: string | null;
}
