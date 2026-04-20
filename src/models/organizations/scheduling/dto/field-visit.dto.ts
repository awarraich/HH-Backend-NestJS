import {
  IsInt,
  IsOptional,
  IsString,
  Matches,
  MaxLength,
  Min,
} from 'class-validator';
import { Type } from 'class-transformer';
import {
  CreateScheduledTaskBase,
  UpdateScheduledTaskBase,
  QueryScheduledTaskBase,
} from './scheduled-task-base.dto';

export class FieldVisitDetailsDto {
  @IsString()
  @MaxLength(128)
  visit_type: string;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  duration_minutes?: number;

  @IsOptional()
  @IsString()
  @Matches(/^\d{2}:\d{2}$/, { message: 'time_window_start must be HH:MM' })
  time_window_start?: string;

  @IsOptional()
  @IsString()
  @Matches(/^\d{2}:\d{2}$/, { message: 'time_window_end must be HH:MM' })
  time_window_end?: string;
}

// `details` is inherited from the base as `Record<string, unknown>`.
// `FieldVisitDetailsDto` above documents the expected shape.
export class CreateFieldVisitDto extends CreateScheduledTaskBase {}

export class UpdateFieldVisitDto extends UpdateScheduledTaskBase {}

export class QueryFieldVisitDto extends QueryScheduledTaskBase {
  @IsOptional()
  @IsString()
  visit_type?: string;
}
