import { IsOptional, IsString, MaxLength } from 'class-validator';

export class ConfirmCompanyProfileGalleryUploadDto {
  @IsString()
  @MaxLength(1024)
  key!: string;

  @IsOptional()
  @IsString()
  @MaxLength(500)
  caption?: string;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  category?: string;
}
