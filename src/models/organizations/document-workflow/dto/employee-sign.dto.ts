import { IsString } from 'class-validator';

export class EmployeeSignDto {
  @IsString()
  signature: string;
}
