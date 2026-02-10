import {
  IsString,
  IsOptional,
  IsDateString,
  MaxLength,
  IsIn,
} from 'class-validator';

export class UpdateEmployeeDto {
  @IsOptional()
  @IsString()
  @IsIn(['ADMIN', 'PROVIDER', 'STAFF', 'HR', 'ASSISTANT_HR', 'BILLER', 'SCHEDULER', 'FRONT_DESK', 'OFFICE_STAFF', 'NURSE'])
  role?: string;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  department?: string;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  position_title?: string;

  @IsOptional()
  @IsDateString()
  start_date?: string;

  @IsOptional()
  @IsDateString()
  end_date?: string;
}

