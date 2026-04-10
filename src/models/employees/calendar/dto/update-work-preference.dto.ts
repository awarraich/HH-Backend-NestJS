import { IsOptional, IsInt, IsString, IsBoolean, Min, Max, IsIn } from 'class-validator';

export class UpdateWorkPreferenceDto {
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(168)
  max_hours_per_week?: number;

  @IsOptional()
  @IsString()
  @IsIn(['morning', 'afternoon', 'night', 'flexible'])
  preferred_shift_type?: string;

  @IsOptional()
  @IsBoolean()
  available_for_overtime?: boolean;

  @IsOptional()
  @IsBoolean()
  available_for_on_call?: boolean;
}
