import { IsString, IsOptional, IsBoolean, MaxLength } from 'class-validator';
import { Type } from 'class-transformer';

export class UpdateBedDto {
  @IsOptional()
  @IsString()
  @MaxLength(50)
  bed_number?: string;

  @IsOptional()
  @Type(() => Boolean)
  @IsBoolean()
  is_active?: boolean;
}
