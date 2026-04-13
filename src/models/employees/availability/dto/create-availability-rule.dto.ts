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
} from 'class-validator';

export class CreateAvailabilityRuleDto {
  @IsInt()
  @Min(0)
  @Max(6)
  day_of_week: number;

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
