import {
  IsArray,
  IsBoolean,
  IsOptional,
  IsString,
  MaxLength,
  ValidateNested,
} from 'class-validator';
import { Type } from 'class-transformer';
import {
  OfferLetterFieldUpsertDto,
  SignatureGeolocationDto,
} from './fill-offer-letter-fields.dto';

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

  /** Optional geolocation snapshot, mirroring the authenticated flow so the
   * audit JSON has the same shape regardless of how the signature was
   * submitted. */
  @IsOptional()
  @ValidateNested()
  @Type(() => SignatureGeolocationDto)
  geolocation?: SignatureGeolocationDto;
}
