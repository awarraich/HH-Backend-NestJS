import { IsArray, ValidateNested } from 'class-validator';
import { Type } from 'class-transformer';
import { OfferLetterFieldUpsertDto } from './fill-offer-letter-fields.dto';

/** Public (token-gated) fill payload — role is derived from the token. */
export class FillOfferLetterByTokenDto {
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => OfferLetterFieldUpsertDto)
  fields: OfferLetterFieldUpsertDto[];
}
