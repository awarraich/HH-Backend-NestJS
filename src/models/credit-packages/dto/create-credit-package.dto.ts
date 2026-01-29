import {
  IsString,
  IsNotEmpty,
  IsInt,
  IsNumber,
  IsBoolean,
  Min,
  MaxLength,
  IsOptional,
} from 'class-validator';

export class CreateCreditPackageDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(100)
  name: string;

  @IsInt()
  @Min(1)
  credits: number;

  @IsNumber({ maxDecimalPlaces: 2 })
  @Min(0.01)
  price_usd: number;

  @IsString()
  @IsNotEmpty()
  @MaxLength(100)
  stripe_price_id: string;

  @IsBoolean()
  @IsOptional()
  is_active?: boolean;
}

