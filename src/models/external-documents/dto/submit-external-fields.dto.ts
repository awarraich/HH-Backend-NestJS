import {
  IsUUID,
  IsArray,
  ValidateNested,
  IsString,
  IsNotEmpty,
  IsOptional,
  IsNumber,
  IsISO8601,
} from 'class-validator';
import { Type } from 'class-transformer';

export class FieldValueItem {
  @IsString()
  @IsNotEmpty()
  fieldId: string;

  @IsNotEmpty()
  value: any;
}

/** Geolocation captured at sign time, mirroring the offer-letter shape so
 *  the audit JSON is uniform across flows. */
export class DocumentSignatureGeolocationDto {
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

export class SubmitExternalFieldsDto {
  @IsUUID()
  userId: string;

  @IsUUID()
  roleId: string;

  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => FieldValueItem)
  fields: FieldValueItem[];

  /** Optional geolocation snapshot for the SignedDocumentInfo audit block. */
  @IsOptional()
  @ValidateNested()
  @Type(() => DocumentSignatureGeolocationDto)
  geolocation?: DocumentSignatureGeolocationDto;
}
