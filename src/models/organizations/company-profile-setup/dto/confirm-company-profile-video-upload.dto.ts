import { IsOptional, IsString, MaxLength } from 'class-validator';

export class ConfirmCompanyProfileVideoUploadDto {
  @IsString()
  @MaxLength(1024)
  key!: string;

  @IsString()
  @MaxLength(255)
  title!: string;

  @IsOptional()
  @IsString()
  @MaxLength(2000)
  description?: string;

  @IsOptional()
  @IsString()
  @MaxLength(20)
  duration?: string;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  category?: string;
}
