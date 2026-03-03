import { IsOptional, IsIn } from 'class-validator';

const RECIPIENT_TYPES = [
  'organization',
  'lab',
  'doctor',
  'clinical',
  'therapist',
] as const;

export class QueryRecipientsDto {
  @IsOptional()
  @IsIn(RECIPIENT_TYPES)
  category?: (typeof RECIPIENT_TYPES)[number];
}
