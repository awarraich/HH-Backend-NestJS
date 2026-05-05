import { IsString, IsOptional, MaxLength, Matches } from 'class-validator';

export class UpdateOrganizationDto {
  @IsString()
  @IsOptional()
  @MaxLength(255)
  organization_name?: string;

  @IsString()
  @IsOptional()
  @MaxLength(20)
  tax_id?: string;

  @IsString()
  @IsOptional()
  @MaxLength(50)
  registration_number?: string;

  @IsString()
  @IsOptional()
  @MaxLength(200)
  @Matches(/^https?:\/\/.+/, {
    message: 'Website must be a valid URL starting with http:// or https://',
  })
  website?: string;

  @IsString()
  @IsOptional()
  description?: string;

  /**
   * IANA timezone the clinic operates in (e.g. "America/Los_Angeles",
   * "America/New_York", "Asia/Karachi"). Validated against Node's built-in
   * Intl.DateTimeFormat zone list — a typo here would silently break the
   * agent's "today is …" computation, so we reject up-front.
   */
  @IsString()
  @IsOptional()
  @MaxLength(100)
  @Matches(/^[A-Za-z]+(?:[/_+\-][A-Za-z0-9_+\-]+)+$/, {
    message:
      'timezone must be a valid IANA zone name (e.g. "America/Los_Angeles")',
  })
  timezone?: string;
}
