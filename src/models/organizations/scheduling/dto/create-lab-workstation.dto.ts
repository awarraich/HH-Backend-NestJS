import { IsString, IsNotEmpty, IsOptional, IsBoolean, IsInt, IsArray, MaxLength, Min } from 'class-validator';
import { Type } from 'class-transformer';

export class CreateLabWorkstationDto {
  @IsNotEmpty()
  @IsString()
  @MaxLength(255)
  name: string;

  @IsOptional()
  @IsString()
  equipment?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  workstation_type?: string;

  @IsOptional()
  @Type(() => Boolean)
  @IsBoolean()
  is_active?: boolean;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  sort_order?: number;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  shift_ids?: string[];
}
