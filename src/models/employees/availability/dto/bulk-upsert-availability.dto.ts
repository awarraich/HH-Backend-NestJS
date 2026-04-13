import { Type } from 'class-transformer';
import { IsArray, IsOptional, IsUUID, ValidateNested } from 'class-validator';
import { CreateAvailabilityRuleDto } from './create-availability-rule.dto';

export class BulkUpsertAvailabilityDto {
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => CreateAvailabilityRuleDto)
  rules: CreateAvailabilityRuleDto[];

  @IsOptional()
  @IsUUID()
  organization_id?: string;
}
