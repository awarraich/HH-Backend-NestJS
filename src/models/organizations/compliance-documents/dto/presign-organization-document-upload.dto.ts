import { IsString, MaxLength } from 'class-validator';

export class PresignOrganizationDocumentUploadDto {
  @IsString()
  @MaxLength(255)
  filename!: string;

  @IsString()
  @MaxLength(127)
  contentType!: string;
}
