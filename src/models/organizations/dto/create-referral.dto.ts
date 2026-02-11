import {
  IsString,
  IsNotEmpty,
  IsOptional,
  IsArray,
  IsUUID,
  IsInt,
  MaxLength,
  ValidateNested,
  ArrayMinSize,
} from 'class-validator';
import { Type } from 'class-transformer';
import { CreatePatientForReferralDto } from './create-patient-for-referral.dto';
import { ReferralDocumentItemDto } from './referral-document-item.dto';

export class CreateReferralDto {
  @IsOptional()
  @IsUUID()
  patient_id?: string;

  @IsOptional()
  @ValidateNested()
  @Type(() => CreatePatientForReferralDto)
  patient?: CreatePatientForReferralDto;

  @IsInt()
  @Type(() => Number)
  organization_type_id: number;

  @IsArray()
  @ArrayMinSize(1)
  @IsUUID('4', { each: true })
  receiving_organization_ids: string[];

  @IsString()
  @IsNotEmpty()
  @MaxLength(20)
  urgency: string;

  @IsOptional()
  @IsString()
  @MaxLength(200)
  insurance_provider?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  estimated_cost?: string;

  @IsString()
  @IsNotEmpty()
  notes: string;

  @IsOptional()
  @IsString()
  @MaxLength(30)
  level_of_care?: string;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  disciplines?: string[];

  /** Patient/referral documents to include (file_name + file_url from prior upload). */
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => ReferralDocumentItemDto)
  documents?: ReferralDocumentItemDto[];
}
