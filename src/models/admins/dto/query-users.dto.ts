import { IsOptional, IsNumber, Min, Max, IsString, IsIn } from 'class-validator';
import { Type } from 'class-transformer';

/** Filter by user association type: organization owner, staff, or employee */
export const USER_TYPE_FILTERS = ['organization', 'employee', 'staff'] as const;
export type UserTypeFilter = (typeof USER_TYPE_FILTERS)[number];

export class QueryUsersDto {
  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  @Min(1)
  page?: number = 1;

  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  @Min(1)
  @Max(100)
  limit?: number = 20;

  @IsOptional()
  @IsString()
  search?: string;

  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  roleId?: number;

  /** Filter by type: organization (owner), employee, or staff */
  @IsOptional()
  @IsIn(USER_TYPE_FILTERS)
  userType?: UserTypeFilter;

  /** Filter users associated with an organization whose name contains this (case-insensitive) */
  @IsOptional()
  @IsString()
  organizationName?: string;
}
