import { IsOptional, IsString, IsUUID, MaxLength, IsIn } from 'class-validator';

export class UpdateOrganizationStaffDto {
  @IsOptional()
  @IsString()
  @IsIn(['ACTIVE', 'INACTIVE', 'TERMINATED'])
  status?: string;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  department?: string;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  position_title?: string;
}
