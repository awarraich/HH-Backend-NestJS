import {
  IsString,
  IsOptional,
  IsInt,
  Min,
  Max,
  MaxLength,
  IsIn,
  IsUrl,
  IsBoolean,
  IsArray,
  ValidateNested,
} from 'class-validator';
import { Type } from 'class-transformer';
import {
  INSERVICE_COMPLETION_FREQUENCIES,
  InserviceTrainingPdfFileDto,
} from './create-inservice-training.dto';

export class ExistingFileTitleDto {
  @IsString()
  file_path: string;

  @IsString()
  @MaxLength(255)
  title: string;
}

export class UpdateInserviceTrainingDto {
  @IsOptional()
  @IsString()
  @MaxLength(255)
  title?: string;

  @IsOptional()
  @IsString()
  description?: string;

  @IsOptional()
  @IsString()
  @IsIn(INSERVICE_COMPLETION_FREQUENCIES)
  completion_frequency?: string;

  @IsOptional()
  @IsArray()
  @IsUrl({}, { each: true })
  @MaxLength(2048, { each: true })
  video_urls?: string[];

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  @MaxLength(255, { each: true })
  video_titles?: string[];

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  @MaxLength(255, { each: true })
  file_titles?: string[];

  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => ExistingFileTitleDto)
  existing_file_titles?: ExistingFileTitleDto[];

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  remove_file_paths?: string[];

  @IsOptional()
  @IsInt()
  @Min(0)
  sort_order?: number;

  @IsOptional()
  @IsBoolean()
  is_active?: boolean;

  @IsOptional()
  @IsBoolean()
  has_quiz?: boolean;

  @IsOptional()
  @IsInt()
  @Min(0)
  @Max(100)
  passing_score_percent?: number | null;

  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => InserviceTrainingPdfFileDto)
  pdf_files?: InserviceTrainingPdfFileDto[];

  @IsOptional()
  @IsBoolean()
  is_deletable?: boolean;
}
