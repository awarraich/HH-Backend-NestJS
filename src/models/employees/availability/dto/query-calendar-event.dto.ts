import { IsOptional, IsString, IsInt, Min, Max, IsUUID, IsIn } from 'class-validator';
import { Type } from 'class-transformer';

export class QueryCalendarEventDto {
  @IsOptional()
  @IsString()
  from_date?: string;

  @IsOptional()
  @IsString()
  to_date?: string;

  @IsOptional()
  @IsString()
  @IsIn(['general', 'visit', 'shift', 'meeting', 'personal'])
  event_type?: string;

  @IsOptional()
  @IsString()
  @IsIn(['active', 'cancelled'])
  status?: string;

  @IsOptional()
  @IsUUID()
  organization_id?: string;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  page?: number = 1;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(100)
  limit?: number = 50;
}
