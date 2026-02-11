import {
  IsNotEmpty,
  IsString,
  IsIn,
} from 'class-validator';

export class UpdateEmployeeStatusDto {
  @IsNotEmpty()
  @IsString()
  @IsIn(['ACTIVE', 'INVITED', 'INACTIVE', 'TERMINATED'])
  status: string;
}

