import {
  IsString,
  IsNotEmpty,
  IsBoolean,
  IsOptional,
  IsInt,
  Min,
  MaxLength,
} from 'class-validator';

export class CreateHrDocumentTypeDto {
  @IsNotEmpty()
  @IsString()
  @MaxLength(20)
  code: string;

  @IsNotEmpty()
  @IsString()
  @MaxLength(255)
  name: string;

  @IsOptional()
  @IsBoolean()
  has_expiration?: boolean;

  @IsOptional()
  @IsBoolean()
  is_required?: boolean;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  category?: string;

  @IsOptional()
  @IsInt()
  @Min(0)
  sort_order?: number;

  @IsOptional()
  @IsBoolean()
  is_deletable?: boolean;
}
