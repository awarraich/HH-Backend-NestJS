import { IsString, IsNotEmpty, IsOptional, IsBoolean, IsUUID, IsDateString, MaxLength } from 'class-validator';
import { Transform } from 'class-transformer';

export class CreateOrganizationDocumentDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(255)
  document_name: string;

  @IsUUID()
  @IsNotEmpty()
  category_id: string;

  @IsBoolean()
  @IsOptional()
  @Transform(({ value }) => value === 'true' || value === true)
  is_required?: boolean;

  @IsBoolean()
  @IsOptional()
  @Transform(({ value }) => value === 'true' || value === true)
  has_expiration?: boolean;

  @IsDateString()
  @IsOptional()
  expiration_date?: string;
}
