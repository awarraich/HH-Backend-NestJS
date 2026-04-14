import { IsOptional, IsString, IsUUID, MaxLength, IsIn, IsArray, IsBoolean } from 'class-validator';

export class UpdateOrganizationStaffDto {
  @IsOptional()
  @IsString()
  @IsIn(['ACTIVE', 'INACTIVE', 'TERMINATED'])
  status?: string;

  @IsOptional()
  @IsArray()
  @IsUUID('4', { each: true })
  feature_ids?: string[];

  @IsOptional()
  @IsString()
  @MaxLength(100)
  department?: string;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  position_title?: string;

  @IsOptional()
  @IsBoolean()
  is_supervisor?: boolean;
}
