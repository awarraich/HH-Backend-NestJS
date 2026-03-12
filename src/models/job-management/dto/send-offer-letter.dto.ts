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
}
