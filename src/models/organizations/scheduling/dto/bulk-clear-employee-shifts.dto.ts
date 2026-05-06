import { IsOptional, IsString, IsUUID, Matches } from 'class-validator';

/**
 * Atomic bulk-clear for employee_shift rows. Used by the Bed Map "Clear
 * room" action so a manager can wipe a whole room's coverage in one
 * round-trip instead of N sequential DELETEs.
 *
 * Scope: at minimum, shift_id + scheduled_date are required. Pass room_id
 * to clear a single room, or station_id to clear an entire station for
 * that shift+date. If neither room_id nor station_id is provided the
 * service refuses (we won't blow away an entire shift by accident).
 */
export class BulkClearEmployeeShiftsDto {
  @IsUUID('4')
  shift_id: string;

  @IsString()
  @Matches(/^\d{4}-\d{2}-\d{2}$/, { message: 'scheduled_date must be YYYY-MM-DD' })
  scheduled_date: string;

  @IsOptional()
  @IsUUID('4')
  room_id?: string;

  @IsOptional()
  @IsUUID('4')
  station_id?: string;
}
