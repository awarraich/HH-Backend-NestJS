import { IsNotEmpty, IsInt, Min } from 'class-validator';
import { Type } from 'class-transformer';

export class AssignRoleDto {
  @IsNotEmpty()
  @IsInt()
  @Min(1)
  @Type(() => Number)
  role_id: number;
}

