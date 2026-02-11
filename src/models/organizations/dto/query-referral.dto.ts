import { IsOptional, IsString, IsInt, Min, Max, IsIn, IsBoolean } from 'class-validator';
import { Type, Transform } from 'class-transformer';

export class QueryReferralDto {
  @IsString()
  @IsIn(['sent', 'received'])
  scope: 'sent' | 'received';

  @IsOptional()
  @IsString()
  @IsIn(['pending', 'assigned', 'accepted', 'declined', 'negotiation'])
  status?: string;

  /** When scope=received, filter to referrals assigned to the current organization. */
  @IsOptional()
  @IsBoolean()
  @Transform(({ value }) =>
    value === undefined || value === '' ? undefined : value === 'true' || value === true,
  )
  assigned_to_me?: boolean;

  @IsOptional()
  @IsInt()
  @Type(() => Number)
  organization_type_id?: number;

  @IsOptional()
  @IsString()
  search?: string;

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
