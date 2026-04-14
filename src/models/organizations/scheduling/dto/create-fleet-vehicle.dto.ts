import { IsString, IsNotEmpty, IsOptional, IsBoolean, IsInt, IsArray, MaxLength, Min } from 'class-validator';
import { Type } from 'class-transformer';

export class CreateFleetVehicleDto {
  @IsNotEmpty()
  @IsString()
  @MaxLength(255)
  name: string;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  vehicle_id?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  vehicle_type?: string;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  capacity?: number;

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
