import { IsEmail, IsOptional, IsString, MaxLength } from 'class-validator';

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
  @IsString()
  @MaxLength(2000)
  message?: string;
}
