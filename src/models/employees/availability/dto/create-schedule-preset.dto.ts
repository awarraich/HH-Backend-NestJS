import { IsString, IsNotEmpty, IsObject, MaxLength } from 'class-validator';

export class CreateSchedulePresetDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(100)
  name: string;

  @IsObject()
  @IsNotEmpty()
  week_pattern: Record<string, unknown>;
}
