import { IsEmail, IsIn, IsOptional, IsString, MaxLength } from 'class-validator';

/** Body for POST send-interview-invite: email content from Schedule Interview modal. */
export class SendInterviewInviteDto {
  @IsEmail()
  toEmail: string;

  @IsString()
  @MaxLength(255)
  applicantName: string;

  @IsString()
  @MaxLength(500)
  jobTitle: string;

  @IsString()
  @MaxLength(50)
  interviewDate: string;

  @IsString()
  @MaxLength(50)
  interviewTime: string;

  @IsOptional()
  @IsIn(['in_person', 'video', 'phone'])
  interviewMode?: 'in_person' | 'video' | 'phone';

  @IsOptional()
  @IsString()
  @MaxLength(500)
  interviewLocation?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  interviewDuration?: string;

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
  @MaxLength(100)
  jobType?: string;

  @IsOptional()
  @IsString()
  @MaxLength(200)
  salaryRange?: string;

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
