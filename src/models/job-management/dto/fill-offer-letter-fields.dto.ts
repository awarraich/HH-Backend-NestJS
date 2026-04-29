import {
  IsArray,
  IsBoolean,
  IsISO8601,
  IsNumber,
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

/**
 * Geolocation captured at the moment a signature/initials field was
 * committed. Mirrors the applicant-signature shape so the audit JSON
 * stays uniform across role-filler and applicant flows.
 */
export class SignatureGeolocationDto {
  @IsNumber()
  latitude: number;

  @IsNumber()
  longitude: number;

  @IsOptional()
  @IsNumber()
  accuracy?: number;

  @IsOptional()
  @IsISO8601()
  capturedAt?: string;
}

export class FillOfferLetterFieldsDto {
  @IsUUID()
  roleId: string;

  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => OfferLetterFieldUpsertDto)
  fields: OfferLetterFieldUpsertDto[];

  /**
   * ESIGN consent version (e.g. "role-filler-offer-v1"). Required when
   * any of the fields being written is a signature/initials field. The
   * backend rejects the call if the version is missing or unknown, or if
   * `consentAccepted` is not true.
   */
  @IsOptional()
  @IsString()
  @MaxLength(100)
  consentVersion?: string;

  @IsOptional()
  @IsBoolean()
  consentAccepted?: boolean;

  /**
   * Optional geolocation snapshot — the browser may decline or the user
   * may deny the prompt, in which case the field is absent and the
   * audit JSON records `geolocation: null` so auditors can tell "user
   * denied" apart from "client never asked".
   */
  @IsOptional()
  @ValidateNested()
  @Type(() => SignatureGeolocationDto)
  geolocation?: SignatureGeolocationDto;
}
