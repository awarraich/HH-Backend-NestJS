import { IsString, IsNotEmpty, IsOptional, IsBoolean, MaxLength } from 'class-validator';
import { Type } from 'class-transformer';

export class CreateChairDto {
  @IsNotEmpty()
  @IsString()
  @MaxLength(50)
  chair_number: string;

  @IsOptional()
  @Type(() => Boolean)
  @IsBoolean()
  is_active?: boolean;
}
