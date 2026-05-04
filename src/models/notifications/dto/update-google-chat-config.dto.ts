import { IsArray, IsBoolean, IsIn, IsOptional } from 'class-validator';

const REMINDER_KINDS = ['60d', '30d', '14d', '7d', '1d', 'expired'] as const;
type ReminderKind = (typeof REMINDER_KINDS)[number];

export class UpdateGoogleChatConfigDto {
  @IsArray()
  @IsOptional()
  @IsIn(REMINDER_KINDS, { each: true })
  cadence?: ReminderKind[];

  @IsBoolean()
  @IsOptional()
  fallback_to_email?: boolean;

  @IsBoolean()
  @IsOptional()
  allow_personal_accounts?: boolean;
}
