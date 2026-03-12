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
} from 'class-validator';

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
  @IsString()
  @IsUrl()
  @MaxLength(2048)
  video_url?: string;

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
}
