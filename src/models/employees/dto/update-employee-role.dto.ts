import {
  IsNotEmpty,
  IsString,
  IsIn,
} from 'class-validator';

export class UpdateEmployeeRoleDto {
  @IsNotEmpty()
  @IsString()
  @IsIn(['ADMIN', 'PROVIDER', 'STAFF', 'HR', 'ASSISTANT_HR', 'BILLER', 'SCHEDULER', 'FRONT_DESK', 'OFFICE_STAFF', 'NURSE'])
  role: string;
}

