import { IsUUID } from 'class-validator';

export class SubmitCompetencyRoleV2Dto {
  @IsUUID()
  roleId: string;
}
