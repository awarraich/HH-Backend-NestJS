import { IsOptional, IsString, IsInt, Min, Max, IsIn, IsUUID } from 'class-validator';
import { Type } from 'class-transformer';

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
