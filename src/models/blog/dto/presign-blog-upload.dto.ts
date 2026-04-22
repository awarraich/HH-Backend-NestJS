import { IsString, MaxLength } from 'class-validator';

export class PresignBlogUploadDto {
  @IsString()
  @MaxLength(255)
  filename!: string;

  @IsString()
  @MaxLength(127)
  contentType!: string;
}
