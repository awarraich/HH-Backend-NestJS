import {
  IsString,
  IsNotEmpty,
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

export class InserviceTrainingPdfFileDto {
  @IsString()
  @MaxLength(255)
  file_name!: string;

  @IsString()
  @MaxLength(1024)
  file_path!: string;

  @IsInt()
  @Min(0)
  file_size_bytes!: number;
}

export const INSERVICE_COMPLETION_FREQUENCIES = ['one_time', 'annual', 'quarterly'] as const;
export type InserviceCompletionFrequency = (typeof INSERVICE_COMPLETION_FREQUENCIES)[number];

export const COMPLETION_FREQUENCY_EXPIRY_MONTHS: Record<
  InserviceCompletionFrequency,
  number | null
> = {
  one_time: null,
  annual: 12,
  quarterly: 3,
};

export class CreateInserviceTrainingDto {
  @IsNotEmpty()
  @IsString()
  @MaxLength(20)
  code: string;

  @IsNotEmpty()
  @IsString()
  @MaxLength(255)
  title: string;

  @IsOptional()
  @IsString()
  description?: string;

  @IsNotEmpty()
  @IsString()
  @IsIn(INSERVICE_COMPLETION_FREQUENCIES)
  completion_frequency: InserviceCompletionFrequency;

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
  @IsInt()
  @Min(0)
  sort_order?: number;

  @IsOptional()
  @IsBoolean()
  has_quiz?: boolean;

  @IsOptional()
  @IsInt()
  @Min(0)
  @Max(100)
  passing_score_percent?: number;

  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => InserviceTrainingPdfFileDto)
  pdf_files?: InserviceTrainingPdfFileDto[];
}
