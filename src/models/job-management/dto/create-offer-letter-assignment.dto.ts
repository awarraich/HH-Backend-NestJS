import {
  IsArray,
  IsEnum,
  IsIn,
  IsNotEmpty,
  IsOptional,
  IsString,
  IsUUID,
  MaxLength,
  ValidateNested,
} from 'class-validator';
import { Type } from 'class-transformer';

export const OFFER_RECIPIENT_TYPES = [
  'supervisor',
  'employee',
  'external_employee',
] as const;
export type OfferRecipientTypeDto = (typeof OFFER_RECIPIENT_TYPES)[number];

export class OfferRoleAssigneeDto {
  @IsUUID()
  @IsNotEmpty()
  roleId: string;

  @IsUUID()
  @IsNotEmpty()
  userId: string;

  @IsEnum(OFFER_RECIPIENT_TYPES)
  recipientType: OfferRecipientTypeDto;
}

/** Offer metadata persisted on the job application alongside the assignment. */
export class OfferLetterMetadataDto {
  @IsOptional()
  @IsString()
  @MaxLength(200)
  salary?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  startDate?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  responseDeadline?: string;

  @IsOptional()
  @IsIn(['full_time', 'part_time', 'contract', 'temporary', 'internship'])
  employmentType?: string;

  @IsOptional()
  @IsString()
  @MaxLength(2000)
  benefits?: string;

  @IsOptional()
  @IsString()
  @MaxLength(2000)
  message?: string;
}

export class CreateOfferLetterAssignmentDto {
  @IsUUID()
  @IsNotEmpty()
  templateId: string;

  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => OfferRoleAssigneeDto)
  assignees: OfferRoleAssigneeDto[];

  @IsOptional()
  @ValidateNested()
  @Type(() => OfferLetterMetadataDto)
  offerDetails?: OfferLetterMetadataDto;
}
