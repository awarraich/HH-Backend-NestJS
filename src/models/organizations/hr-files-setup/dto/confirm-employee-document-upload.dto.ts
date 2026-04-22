import { IsInt, IsOptional, IsPositive, IsString, IsUUID, MaxLength } from 'class-validator';

export class ConfirmEmployeeDocumentUploadDto {
  @IsString()
  @MaxLength(1024)
  key!: string;

  @IsString()
  @MaxLength(255)
  file_name!: string;

  @IsUUID()
  document_type_id!: string;

  @IsOptional()
  @IsString()
  @MaxLength(127)
  mime_type?: string;

  @IsOptional()
  @IsInt()
  @IsPositive()
  size_bytes?: number;
}
