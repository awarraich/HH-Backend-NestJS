import { IsInt, IsOptional, IsString, IsUUID, Max, Min } from 'class-validator';
import { Type } from 'class-transformer';

/**
 * Query params for the paginated organization job-applications list.
 *
 * `status` accepts either a concrete status string ("interview", "offer_sent", ...) or the
 * special bucket "offers" which matches any offer-lifecycle state.
 */
export class QueryJobApplicationsDto {
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
  limit?: number = 25;

  @IsOptional()
  @IsString()
  status?: string;

  /** Case-insensitive search across applicant name, email, and job title. */
  @IsOptional()
  @IsString()
  q?: string;

  @IsOptional()
  @IsUUID()
  job_posting_id?: string;
}
