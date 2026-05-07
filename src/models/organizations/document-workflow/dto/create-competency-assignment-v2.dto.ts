import {
  IsArray,
  IsIn,
  IsNotEmpty,
  IsUUID,
  ValidateNested,
} from 'class-validator';
import { Type } from 'class-transformer';

export class CompetencyAssigneeDto {
  @IsUUID()
  @IsNotEmpty()
  roleId: string;

  @IsUUID()
  @IsNotEmpty()
  userId: string;

  /** Drives where the email deep-link routes the assignee. */
  @IsIn(['supervisor', 'employee', 'external_employee'])
  recipientType: 'supervisor' | 'employee' | 'external_employee';
}

export class CreateCompetencyAssignmentV2Dto {
  @IsUUID()
  @IsNotEmpty()
  templateId: string;

  /** The employee whose HR File this workflow is being assigned against. */
  @IsUUID()
  @IsNotEmpty()
  employeeUserId: string;

  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => CompetencyAssigneeDto)
  assignees: CompetencyAssigneeDto[];
}
