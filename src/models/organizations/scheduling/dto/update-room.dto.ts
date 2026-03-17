import { IsString, IsOptional, IsBoolean, IsInt, MaxLength, Min } from 'class-validator';
import { Type } from 'class-transformer';

export class UpdateRoomDto {
  @IsOptional()
  @IsString()
  @MaxLength(100)
  name?: string;

  @IsOptional()
  @IsString()
  @MaxLength(255)
  location_or_wing?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  floor?: string;

  @IsOptional()
  @IsString()
  @MaxLength(20)
  configuration_type?: string;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  beds_per_room?: number;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  chairs_per_room?: number;

  @IsOptional()
  @Type(() => Boolean)
  @IsBoolean()
  is_active?: boolean;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  sort_order?: number;
}
