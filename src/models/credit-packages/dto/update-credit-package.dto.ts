import {
  IsString,
  IsInt,
  IsNumber,
  IsBoolean,
  Min,
  MaxLength,
  IsOptional,
} from 'class-validator';

export class UpdateCreditPackageDto {
  @IsString()
  @IsOptional()
  @MaxLength(100)
  name?: string;

  @IsInt()
  @IsOptional()
  @Min(1)
  credits?: number;

  @IsNumber({ maxDecimalPlaces: 2 })
  @IsOptional()
  @Min(0.01)
  price_usd?: number;

  @IsString()
  @IsOptional()
  @MaxLength(100)
  stripe_price_id?: string;

  @IsBoolean()
  @IsOptional()
  is_active?: boolean;
}

