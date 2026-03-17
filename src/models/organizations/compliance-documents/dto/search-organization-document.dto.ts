import { IsString, IsNotEmpty, IsOptional, IsUUID, IsInt, Min, Max } from 'class-validator';

export class SearchOrganizationDocumentDto {
  @IsString()
  @IsNotEmpty()
  query: string;

  @IsUUID()
  @IsOptional()
  category_id?: string;

  @IsInt()
  @IsOptional()
  @Min(1)
  @Max(20)
  limit?: number = 10;
}
