import { IsNotEmpty, IsInt, Min, IsUUID } from 'class-validator';
import { Type } from 'class-transformer';

export class AssignOrganizationTypeDto {
  @IsNotEmpty()
  @IsUUID()
  organization_id: string;

  @IsNotEmpty()
  @IsInt()
  @Min(1)
  @Type(() => Number)
  organization_type_id: number;
}