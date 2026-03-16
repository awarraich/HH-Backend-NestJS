import { IsString, IsNotEmpty, IsOptional, IsInt, Min, MaxLength } from 'class-validator';
import { Type } from 'class-transformer';

export class StationRoomItemDto {
  @IsNotEmpty()
  @IsString()
  @MaxLength(100)
  name: string;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  beds?: number;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  chairs?: number;
}
