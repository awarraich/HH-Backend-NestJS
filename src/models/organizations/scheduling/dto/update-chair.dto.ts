import { IsString, IsOptional, IsBoolean, MaxLength } from 'class-validator';
import { Type } from 'class-transformer';

export class UpdateChairDto {
  @IsOptional()
  @IsString()
  @MaxLength(50)
  chair_number?: string;

  @IsOptional()
  @Type(() => Boolean)
  @IsBoolean()
  is_active?: boolean;
}
