import { IsString, MaxLength } from 'class-validator';

export class PresignEmployeeDocumentUploadDto {
  @IsString()
  @MaxLength(255)
  filename!: string;

  @IsString()
  @MaxLength(127)
  contentType!: string;
}
