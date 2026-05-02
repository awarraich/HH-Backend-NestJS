import { IsOptional, IsString, IsUUID, IsInt, Min, Max, Matches } from 'class-validator';
import { Type } from 'class-transformer';

export class QueryMyShiftsDto {
  @IsOptional()
  @IsString()
  @Matches(/^\d{4}-\d{2}-\d{2}$/, { message: 'from_date must be YYYY-MM-DD' })
  from_date?: string;

  @IsOptional()
  @IsString()
  @Matches(/^\d{4}-\d{2}-\d{2}$/, { message: 'to_date must be YYYY-MM-DD' })
  to_date?: string;

  @IsOptional()
  @IsUUID('4')
  organization_id?: string;

  @IsOptional()
  @IsString()
  status?: string;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  page?: number = 1;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(200)
  limit?: number = 100;
}
