import { IsInt, IsOptional, IsPositive, IsString, MaxLength } from 'class-validator';

export class ReplaceEmployeeDocumentFileDto {
  @IsString()
  @MaxLength(1024)
  key!: string;

  @IsString()
  @MaxLength(255)
  file_name!: string;

  @IsOptional()
  @IsString()
  @MaxLength(127)
  mime_type?: string;

  @IsOptional()
  @IsInt()
  @IsPositive()
  size_bytes?: number;
}
