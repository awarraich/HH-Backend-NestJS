import {
  IsString,
  IsOptional,
  IsBoolean,
  IsUUID,
  IsDateString,
  MaxLength,
  IsIn,
} from 'class-validator';

export class CreateCalendarEventDto {
  @IsString()
  @MaxLength(255)
  title: string;

  @IsOptional()
  @IsString()
  description?: string;

  @IsDateString()
  start_at: string;

  @IsDateString()
  end_at: string;

  @IsOptional()
  @IsBoolean()
  all_day?: boolean;

  @IsOptional()
  @IsString()
  @MaxLength(500)
  location?: string;

  @IsOptional()
  @IsString()
  @IsIn(['general', 'visit', 'shift', 'meeting', 'personal'])
  event_type?: string;

  @IsOptional()
  @IsString()
  @MaxLength(20)
  color?: string;

  @IsOptional()
  @IsString()
  @MaxLength(255)
  recurrence_rule?: string;

  @IsOptional()
  @IsDateString()
  recurrence_end_date?: string;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  timezone?: string;

  @IsOptional()
  @IsUUID()
  organization_id?: string;
}
