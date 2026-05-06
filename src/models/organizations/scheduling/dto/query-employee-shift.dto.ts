import { IsOptional, IsUUID, IsString, IsInt, Min, Max, MaxLength } from 'class-validator';
import { Type } from 'class-transformer';

export class QueryEmployeeShiftDto {
  @IsOptional()
  @IsUUID('4')
  employee_id?: string;

  @IsOptional()
  @IsString()
  status?: string;

  @IsOptional()
  @IsString()
  scheduled_date?: string;

  @IsOptional()
  @IsString()
  from_date?: string;

  @IsOptional()
  @IsString()
  to_date?: string;

  /**
   * Optional location filters. Used by the Bed Map flow on the Employee
   * Scheduling page so the client can fetch only the relevant slice instead
   * of paging the whole shift roster. Existing callers (Grid view) don't
   * pass these and behaviour is unchanged.
   */
  @IsOptional()
  @IsUUID('4')
  station_id?: string;

  @IsOptional()
  @IsUUID('4')
  room_id?: string;

  @IsOptional()
  @IsUUID('4')
  bed_id?: string;

  @IsOptional()
  @IsUUID('4')
  chair_id?: string;

  /** Role code filter (e.g. "RN", "CNA"). Matches `employee_shifts.role`. */
  @IsOptional()
  @IsString()
  @MaxLength(50)
  role?: string;

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
  limit?: number = 20;
}
