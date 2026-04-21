import {
  IsArray,
  IsBoolean,
  IsOptional,
  IsString,
  MaxLength,
  ValidateNested,
} from 'class-validator';
import { Type } from 'class-transformer';
import { OfferLetterFieldUpsertDto } from './fill-offer-letter-fields.dto';

/** Public (token-gated) fill payload — role is derived from the token. */
export class FillOfferLetterByTokenDto {
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => OfferLetterFieldUpsertDto)
  fields: OfferLetterFieldUpsertDto[];

  /** ESIGN consent metadata. Required when any field being written is a
   * signature/initials type — enforced by the service layer. */
  @IsOptional()
  @IsString()
  @MaxLength(100)
  consentVersion?: string;

  @IsOptional()
  @IsBoolean()
  consentAccepted?: boolean;
}
