import { IsString, IsOptional, IsObject, MaxLength } from 'class-validator';

export class UpdateSchedulePresetDto {
  @IsOptional()
  @IsString()
  @MaxLength(100)
  name?: string;

  @IsOptional()
  @IsObject()
  week_pattern?: Record<string, unknown>;
}
