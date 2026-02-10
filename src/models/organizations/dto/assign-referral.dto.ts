import { IsUUID } from 'class-validator';

export class AssignReferralDto {
  @IsUUID()
  organization_id: string;
}
