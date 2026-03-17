import { IsOptional, IsString, IsInt, IsIn, IsUUID, Min, Max } from 'class-validator';
import { Type } from 'class-transformer';

export class QueryOrganizationDocumentDto {
  @IsOptional()
  @IsString()
  search?: string;

  @IsOptional()
  @IsUUID()
  category_id?: string;

  @IsOptional()
  @IsIn(['valid', 'expired', 'expiring_soon', 'missing'])
  status?: string;

  @IsOptional()
  @IsIn(['category', 'document_name', 'expiration_date', 'created_at'])
  sort_by?: string = 'created_at';

  @IsOptional()
  @IsIn(['asc', 'desc'])
  sort_order?: 'asc' | 'desc' = 'desc';

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
