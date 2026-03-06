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
  ValidateIf,
} from 'class-validator';
import { INSERVICE_COMPLETION_FREQUENCIES } from './create-inservice-training.dto';

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
  @ValidateIf((_o, v) => v != null && v !== '')
  @IsString()
  @IsUrl()
  @MaxLength(2048)
  video_url?: string | null;

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
}
