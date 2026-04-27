import { IsOptional, IsInt, IsString, IsBoolean, IsArray, IsObject, Min, Max, IsIn } from 'class-validator';

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

  // ── Safety & Compliance ───────────────────────────────────────────

  @IsOptional()
  @IsInt()
  @Min(0)
  @Max(24)
  min_rest_hours?: number;

  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(14)
  max_consecutive_days?: number;

  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(24)
  max_hours_per_day?: number;

  @IsOptional()
  @IsString()
  @IsIn(['no', 'sometimes', 'yes'])
  double_shift_preference?: string;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  double_shift_conditions?: string[];

  // ── Work Type & Location ──────────────────────────────────────────

  @IsOptional()
  @IsString()
  @IsIn(['office', 'field', 'both'])
  work_type?: string;

  @IsOptional()
  @IsInt()
  @Min(0)
  @Max(500)
  travel_radius?: number;

  @IsOptional()
  @IsBoolean()
  has_own_vehicle?: boolean;

  @IsOptional()
  @IsBoolean()
  use_company_vehicle?: boolean;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  preferred_areas?: string[];

  @IsOptional()
  @IsObject()
  facilities?: Record<string, boolean>;

  @IsOptional()
  @IsObject()
  weekly_notes?: Record<string, string>;

  // Per-org availability-page UI state. Shape is
  // `Record<orgId, { activePresetId, fourTwoStartDate, fourTwoShifts }>`,
  // but the backend treats it as an opaque jsonb blob — no per-key
  // validation beyond "it's an object."
  @IsOptional()
  @IsObject()
  availability_ui_by_org?: Record<string, Record<string, unknown>>;
}
