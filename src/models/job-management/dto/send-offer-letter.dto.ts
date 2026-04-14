import { IsEmail, IsIn, IsOptional, IsString, MaxLength } from 'class-validator';

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
}
