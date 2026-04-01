import { IsUUID, IsArray, ValidateNested, IsNotEmpty } from 'class-validator';
import { Type } from 'class-transformer';

export class UserRoleAssignment {
  @IsUUID()
  @IsNotEmpty()
  userId: string;

  @IsUUID()
  @IsNotEmpty()
  roleId: string;
}

export class AssignTemplateUsersDto {
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => UserRoleAssignment)
  assignments: UserRoleAssignment[];
}
