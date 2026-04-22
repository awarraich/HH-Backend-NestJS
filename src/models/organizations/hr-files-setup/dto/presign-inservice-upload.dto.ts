import { IsOptional, IsString, IsUUID, MaxLength } from 'class-validator';

export class PresignInserviceUploadDto {
  @IsString()
  @MaxLength(255)
  filename!: string;

  @IsString()
  @MaxLength(127)
  contentType!: string;

  @IsOptional()
  @IsUUID()
  inservice_id?: string;
}
