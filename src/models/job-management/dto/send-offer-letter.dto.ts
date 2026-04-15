import {
  IsEmail,
  IsIn,
  IsInt,
  IsNumber,
  IsOptional,
  IsString,
  MaxLength,
  Min,
  ValidateNested,
} from 'class-validator';
import { Type } from 'class-transformer';

/** PDF signature-box coordinates (points, origin top-left). */
export class SignaturePositionDto {
  @IsInt()
  @Min(1)
  pageNumber: number;

  @IsNumber()
  x: number;

  @IsNumber()
  y: number;

  @IsNumber()
  @Min(1)
  width: number;

  @IsNumber()
  @Min(1)
  height: number;
}

/** Body for POST send-offer: email content from Send Offer modal. */
export class SendOfferLetterDto {
  @IsEmail()
  toEmail: string;

  @IsString()
  @MaxLength(255)
  applicantName: string;

  @IsString()
  @MaxLength(500)
  jobTitle: string;

  @IsString()
  @MaxLength(200)
  salary: string;

  @IsString()
  @MaxLength(50)
  startDate: string;

  @IsString()
  offerContent: string;

  @IsIn(['write', 'upload'])
  offerType: 'write' | 'upload';

  @IsOptional()
  @IsString()
  @MaxLength(2048)
  attachmentUrl?: string;

  @IsOptional()
  @IsString()
  @MaxLength(2000)
  benefits?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  responseDeadline?: string;

  @IsOptional()
  @IsIn(['full_time', 'part_time', 'contract', 'temporary', 'internship'])
  employmentType?: 'full_time' | 'part_time' | 'contract' | 'temporary' | 'internship';

  @IsOptional()
  @IsString()
  @MaxLength(2000)
  message?: string;

  @IsOptional()
  @IsString()
  @MaxLength(255)
  jobLocation?: string;

  @IsOptional()
  @IsString()
  @MaxLength(5000)
  jobDescription?: string;

  @IsOptional()
  @IsString()
  @MaxLength(255)
  organizationName?: string;

  @IsOptional()
  @IsString()
  @MaxLength(255)
  contactName?: string;

  @IsOptional()
  @IsEmail()
  contactEmail?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  contactPhone?: string;

  @IsOptional()
  @ValidateNested()
  @Type(() => SignaturePositionDto)
  signaturePosition?: SignaturePositionDto;
}
