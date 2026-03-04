import { IsOptional, IsString, IsIn } from 'class-validator';

export class UpdateJobPostingDto {
  @IsOptional()
  @IsString()
  @IsIn(['active', 'closed', 'filled'])
  status?: string;
}
