import { IsOptional, IsString, IsInt, Min, Max, IsIn, IsUUID, IsBoolean } from 'class-validator';
import { Type, Transform } from 'class-transformer';

export class QueryEmployeeDto {
  @IsOptional()
  @IsString()
  search?: string;

  @IsOptional()
  @IsUUID()
  provider_role_id?: string;

  @IsOptional()
  @IsString()
  @IsIn(['ACTIVE', 'INVITED', 'INACTIVE', 'TERMINATED'])
  status?: string;

  @IsOptional()
  @IsBoolean()
  @Transform(({ value }) => value === 'true' || value === true)
  include_orphan_employees?: boolean = false;

  @IsOptional()
  @IsInt()
  @Min(1)
  @Type(() => Number)
  page?: number = 1;

  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(100)
  @Type(() => Number)
  limit?: number = 20;
}
