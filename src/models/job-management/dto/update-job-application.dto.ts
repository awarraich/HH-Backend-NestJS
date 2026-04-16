import { IsObject, IsOptional, IsString, MaxLength } from 'class-validator';

/** Update job application (e.g. status for reject / schedule interview / send offer).
 *  `interview_details` and `offer_details` may be merged/replaced atomically alongside a status change. */
export class UpdateJobApplicationDto {
  @IsOptional()
  @IsString()
  @MaxLength(50)
  status?: string;

  /** Interview schedule payload persisted when HR marks status = "interview". */
  @IsOptional()
  @IsObject()
  interview_details?: Record<string, unknown>;

  /** Offer-letter payload persisted when HR marks status = "offer_sent". */
  @IsOptional()
  @IsObject()
  offer_details?: Record<string, unknown>;
}
