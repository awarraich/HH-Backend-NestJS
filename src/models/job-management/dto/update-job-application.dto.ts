import { IsOptional, IsString, MaxLength } from 'class-validator';

/** Update job application (e.g. status for reject / schedule interview / send offer). */
export class UpdateJobApplicationDto {
  @IsOptional()
  @IsString()
  @MaxLength(50)
  status?: string;
}
