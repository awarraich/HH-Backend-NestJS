import {
  IsArray,
  IsOptional,
  IsString,
  IsUUID,
  ValidateNested,
  MaxLength,
} from 'class-validator';
import { Type } from 'class-transformer';

export class OfferLetterFieldUpsertDto {
  @IsString()
  @MaxLength(255)
  fieldId: string;

  @IsOptional()
  @IsString()
  @MaxLength(2_000_000)
  valueText?: string | null;

  @IsOptional()
  valueJson?: Record<string, unknown> | null;
}

export class FillOfferLetterFieldsDto {
  @IsUUID()
  roleId: string;

  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => OfferLetterFieldUpsertDto)
  fields: OfferLetterFieldUpsertDto[];
}
