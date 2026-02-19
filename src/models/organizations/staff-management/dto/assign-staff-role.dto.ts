import { IsNotEmpty, IsUUID } from 'class-validator';

export class AssignStaffRoleDto {
  @IsNotEmpty()
  @IsUUID()
  staff_role_id: string;
}
