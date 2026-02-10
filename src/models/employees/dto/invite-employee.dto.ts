import {
  IsString,
  IsNotEmpty,
  IsEmail,
  IsIn,
  MaxLength,
  IsOptional,
} from 'class-validator';

export class InviteEmployeeDto {
  @IsNotEmpty()
  @IsEmail()
  email: string;

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
}

