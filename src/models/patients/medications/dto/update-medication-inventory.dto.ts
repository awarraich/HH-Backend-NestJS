import { IsString, IsOptional, IsInt, Min, MaxLength } from 'class-validator';
import { Type } from 'class-transformer';

export class UpdateMedicationInventoryDto {
  @IsOptional()
  @IsInt()
  @Min(0)
  @Type(() => Number)
  onHand?: number;

  @IsOptional()
  @IsInt()
  @Min(1)
  @Type(() => Number)
  totalQuantity?: number;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  unit?: string;
}
