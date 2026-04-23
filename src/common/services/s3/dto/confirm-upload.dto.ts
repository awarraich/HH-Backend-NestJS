import { IsInt, IsOptional, IsPositive, IsString, MaxLength } from 'class-validator';

export class ConfirmUploadDto {
  @IsString()
  @MaxLength(1024)
  key!: string;

  @IsString()
  @MaxLength(255)
  fileName!: string;

  @IsOptional()
  @IsString()
  @MaxLength(127)
  mimeType?: string;

  @IsOptional()
  @IsInt()
  @IsPositive()
  sizeBytes?: number;
}
