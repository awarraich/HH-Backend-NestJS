import { IsUUID, IsNotEmpty, IsOptional, IsString, MaxLength, Matches } from 'class-validator';

export class CreateEmployeeShiftDto {
  @IsNotEmpty()
  @IsUUID('4')
  employee_id: string;

  @IsOptional()
  @IsUUID('4')
  department_id?: string;

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

  @IsOptional()
  @IsString()
  @Matches(/^\d{4}-\d{2}-\d{2}$/, { message: 'scheduled_date must be YYYY-MM-DD' })
  scheduled_date?: string;

  @IsOptional()
  @IsString()
  @MaxLength(20)
  status?: string;

  @IsOptional()
  @IsString()
  notes?: string;
}
