import {
  IsInt,
  IsNumber,
  IsOptional,
  IsString,
  MaxLength,
  Min,
  ValidateNested,
} from 'class-validator';
import { Type } from 'class-transformer';

export class SignaturePositionInputDto {
  @IsInt()
  @Min(1)
  pageNumber!: number;

  @IsNumber()
  x!: number;

  @IsNumber()
  y!: number;

  @IsNumber()
  @Min(1)
  width!: number;

  @IsNumber()
  @Min(1)
  height!: number;
}

export class SignOfferLetterDto {
  /** Base64-encoded PNG of the candidate's signature (with or without data URI prefix). */
  @IsString()
  @MaxLength(2_000_000)
  signatureImageBase64!: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  signedAt?: string;

  /** Candidate-chosen signature placement (PDF points, origin top-left). */
  @IsOptional()
  @ValidateNested()
  @Type(() => SignaturePositionInputDto)
  signaturePosition?: SignaturePositionInputDto;
}
