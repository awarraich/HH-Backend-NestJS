import { IsIn, IsOptional, IsString, MaxLength } from 'class-validator';

export const DEFAULT_ALLOWED_CONTENT_TYPES = [
  'image/jpeg',
  'image/jpg',
  'image/png',
  'image/gif',
  'image/webp',
  'image/svg+xml',
  'application/pdf',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.ms-excel',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'text/plain',
  'text/csv',
  'video/mp4',
  'video/webm',
  'video/quicktime',
  'video/mpeg',
  'video/ogg',
  'video/x-m4v',
] as const;

export class PresignUploadDto {
  @IsString()
  @MaxLength(255)
  filename!: string;

  @IsString()
  @IsIn(DEFAULT_ALLOWED_CONTENT_TYPES as unknown as string[], {
    message: 'content type not allowed',
  })
  contentType!: string;
}
