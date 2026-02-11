import { IsString, IsNotEmpty, MaxLength } from 'class-validator';

export class ReferralDocumentItemDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(255)
  file_name: string;

  @IsString()
  @IsNotEmpty()
  @MaxLength(2048)
  file_url: string;
}
