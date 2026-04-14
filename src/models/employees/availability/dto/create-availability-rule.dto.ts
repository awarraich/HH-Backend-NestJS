import {
  IsInt,
  IsString,
  IsOptional,
  IsBoolean,
  IsUUID,
  IsDateString,
  Min,
  Max,
  MaxLength,
  IsMilitaryTime,
  IsIn,
  ValidateIf,
  Matches,
} from 'class-validator';

export class CreateAvailabilityRuleDto {
  /**
   * Specific date for one-off availability (YYYY-MM-DD).
   * When provided, `day_of_week` is auto-derived and can be omitted.
   */
  @IsOptional()
  @Matches(/^\d{4}-\d{2}-\d{2}$/, { message: 'date must be YYYY-MM-DD' })
  date?: string;

  /**
   * Day of week (0 = SUN … 6 = SAT). Required for recurring rules
   * when `date` is not provided.
   */
  @ValidateIf((o) => !o.date)
  @IsInt()
  @Min(0)
  @Max(6)
  day_of_week?: number;

  @IsMilitaryTime()
  start_time: string;

  @IsMilitaryTime()
  end_time: string;

  @IsOptional()
  @IsBoolean()
  is_available?: boolean;

  @IsOptional()
  @IsString()
  @IsIn(['morning', 'afternoon', 'night'])
  @MaxLength(50)
  shift_type?: string;

  @IsOptional()
  @IsDateString()
  effective_from?: string;

  @IsOptional()
  @IsDateString()
  effective_until?: string;

  @IsOptional()
  @IsUUID()
  organization_id?: string;
}
