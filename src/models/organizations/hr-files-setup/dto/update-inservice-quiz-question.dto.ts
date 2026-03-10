import { IsString, IsOptional, IsInt, Min, IsIn, IsArray, IsBoolean } from 'class-validator';
import { INSERVICE_QUESTION_TYPES } from '../entities/inservice-quiz-question.entity';

export class UpdateInserviceQuizQuestionDto {
  @IsOptional()
  @IsString()
  @IsIn(INSERVICE_QUESTION_TYPES)
  question_type?: string;

  @IsOptional()
  @IsString()
  question_text?: string;

  @IsOptional()
  @IsInt()
  @Min(0)
  sort_order?: number;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  options?: string[];

  @IsOptional()
  @IsInt()
  @Min(0)
  correct_answer_index?: number;

  @IsOptional()
  @IsBoolean()
  correct_boolean?: boolean;

  @IsOptional()
  @IsString()
  correct_text?: string;

  @IsOptional()
  @IsString()
  sample_answer?: string;

  @IsOptional()
  left_column?: unknown;

  @IsOptional()
  right_column?: unknown;

  @IsOptional()
  correct_matches?: unknown;

  @IsOptional()
  @IsString()
  explanation?: string;
}
