import {
  IsEmail,
  IsIn,
  IsInt,
  IsOptional,
  IsString,
  Matches,
  Max,
  MaxLength,
  Min,
} from 'class-validator';

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
  @IsIn(['zoom', 'google_meet', 'teams'])
  videoPlatform?: 'zoom' | 'google_meet' | 'teams';

  /**
   * IANA timezone the candidate's date/time are expressed in. Required for
   * correct .ics rendering and for Zoom/Meet API payloads.
   * Falls back to "UTC" server-side if omitted.
   */
  @IsOptional()
  @IsString()
  @MaxLength(64)
  @Matches(/^[A-Za-z_]+\/[A-Za-z_\-+0-9\/]+$|^UTC$/, {
    message: 'interviewTimezone must be an IANA zone like America/New_York',
  })
  interviewTimezone?: string;

  /** Numeric duration in minutes — used by calendar APIs + .ics DTEND. */
  @IsOptional()
  @IsInt()
  @Min(5)
  @Max(1440)
  interviewDurationMinutes?: number;

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
