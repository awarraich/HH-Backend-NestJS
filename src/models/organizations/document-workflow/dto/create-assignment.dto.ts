import { IsUUID } from 'class-validator';

export class CreateAssignmentDto {
  @IsUUID()
  templateId: string;

  @IsUUID()
  supervisorId: string;
}
