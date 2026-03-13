import { IsUUID, IsNotEmpty, IsOptional, IsString, IsDateString, MaxLength } from 'class-validator';

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
  @IsString()
  @MaxLength(20)
  status?: string;

  @IsOptional()
  @IsString()
  notes?: string;
}
