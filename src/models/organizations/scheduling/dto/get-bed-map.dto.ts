import { IsOptional, IsString, IsUUID, Matches } from 'class-validator';

/**
 * Query for the comprehensive Bed Map snapshot endpoint.
 * Required: station_id (we always render rooms for one station at a time).
 * Optional: shift_id + scheduled_date — when both are present, the response
 * includes the assignments + stats for that shift+date. When omitted, only
 * the room/bed/chair layout is returned (assignments=[], stats zeroed) so
 * the manager can still pick a shift afterward.
 */
export class GetBedMapDto {
  @IsUUID('4')
  station_id: string;

  @IsOptional()
  @IsUUID('4')
  shift_id?: string;

  @IsOptional()
  @IsString()
  @Matches(/^\d{4}-\d{2}-\d{2}$/, { message: 'scheduled_date must be YYYY-MM-DD' })
  scheduled_date?: string;
}
