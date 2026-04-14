import { IsOptional, IsString, IsInt, Min, Max, IsUUID, IsIn } from 'class-validator';
import { Type } from 'class-transformer';

export class QueryTimeOffRequestDto {
  @IsOptional()
  @IsString()
  @IsIn(['pending', 'approved', 'denied'])
  status?: string;

  @IsOptional()
  @IsString()
  from_date?: string;

  @IsOptional()
  @IsString()
  to_date?: string;

  @IsOptional()
  @IsUUID()
  organization_id?: string;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  page?: number = 1;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(100)
  limit?: number = 20;
}
