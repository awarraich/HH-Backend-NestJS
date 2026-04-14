import {
  IsString,
  IsOptional,
  IsDateString,
  IsArray,
  IsIn,
  MaxLength,
  IsInt,
  Min,
  Max,
} from 'class-validator';
import { Type } from 'class-transformer';

const RECURRENCE_TYPES = ['ONE_TIME', 'FULL_WEEK', 'WEEKDAYS', 'WEEKENDS', 'CUSTOM'] as const;

export class UpdateShiftDto {
  @IsOptional()
  @IsDateString()
  start_at?: string;

  @IsOptional()
  @IsDateString()
  end_at?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  shift_type?: string;

  @IsOptional()
  @IsString()
  @MaxLength(255)
  name?: string;

  @IsOptional()
  @IsString()
  @MaxLength(20)
  status?: string;

  @IsOptional()
  @IsString()
  @IsIn(RECURRENCE_TYPES)
  recurrence_type?: string;

  @IsOptional()
  @IsDateString()
  recurrence_start_date?: string;

  @IsOptional()
  @IsDateString()
  recurrence_end_date?: string;

  @IsOptional()
  @IsArray()
  @IsInt({ each: true })
  @Min(1, { each: true })
  @Max(7, { each: true })
  @Type(() => Number)
  recurrence_days?: number[];

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  assigned_roles?: string[];

  @IsOptional()
  @IsString()
  timezone?: string;
}
