import {
  IsString,
  IsNotEmpty,
  IsOptional,
  IsUUID,
  IsDateString,
  MaxLength,
  IsIn,
} from 'class-validator';

export class CreateEmployeeDto {
  @IsNotEmpty()
  @IsUUID()
  user_id: string;

  @IsNotEmpty()
  @IsString()
  @IsIn(['ADMIN', 'PROVIDER', 'STAFF', 'HR', 'ASSISTANT_HR', 'BILLER', 'SCHEDULER', 'FRONT_DESK', 'OFFICE_STAFF', 'NURSE'])
  role: string;

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
}

