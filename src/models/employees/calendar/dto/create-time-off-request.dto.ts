import { IsString, IsOptional, IsUUID, IsDateString } from 'class-validator';

export class CreateTimeOffRequestDto {
  @IsDateString()
  start_date: string;

  @IsDateString()
  end_date: string;

  @IsOptional()
  @IsString()
  reason?: string;

  @IsOptional()
  @IsUUID()
  organization_id?: string;
}
