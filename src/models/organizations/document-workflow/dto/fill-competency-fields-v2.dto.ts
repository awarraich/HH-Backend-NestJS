import {
  IsArray,
  IsBoolean,
  IsNumber,
  IsObject,
  IsOptional,
  IsString,
  IsUUID,
  ValidateNested,
} from 'class-validator';
import { Type } from 'class-transformer';

export class CompetencyFieldValueDto {
  @IsString()
  fieldId: string;

  @IsOptional()
  @IsString()
  valueText?: string | null;

  @IsOptional()
  @IsObject()
  valueJson?: Record<string, unknown> | null;
}

export class CompetencyGeolocationDto {
  @IsNumber()
  latitude: number;

  @IsNumber()
  longitude: number;

  @IsOptional()
  @IsNumber()
  accuracy?: number | null;

  @IsOptional()
  @IsString()
  capturedAt?: string | null;
}

export class FillCompetencyFieldsV2Dto {
  @IsUUID()
  roleId: string;

  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => CompetencyFieldValueDto)
  fields: CompetencyFieldValueDto[];

  /** Required when any field being saved is a signature/initials field. */
  @IsOptional()
  @IsString()
  consentVersion?: string;

  @IsOptional()
  @IsBoolean()
  consentAccepted?: boolean;

  @IsOptional()
  @ValidateNested()
  @Type(() => CompetencyGeolocationDto)
  geolocation?: CompetencyGeolocationDto;
}

export class FillCompetencyFieldsByTokenDto extends FillCompetencyFieldsV2Dto {
  // Same shape as the authed version — kept as a separate class so we can
  // strip the roleId requirement later if the token flow ever needs it.
}
