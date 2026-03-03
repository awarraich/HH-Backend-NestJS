import {
  IsString,
  IsNotEmpty,
  IsOptional,
  IsUUID,
  IsIn,
  MaxLength,
} from 'class-validator';

const RECIPIENT_TYPES = [
  'organization',
  'lab',
  'doctor',
  'clinical',
  'therapist',
] as const;

export class CreateConversationDto {
  @IsOptional()
  @IsUUID()
  organizationId?: string;

  @IsOptional()
  @IsUUID()
  patientId?: string;

  @IsString()
  @IsNotEmpty()
  @IsIn(RECIPIENT_TYPES)
  recipientType: (typeof RECIPIENT_TYPES)[number];

  @IsOptional()
  @IsUUID()
  recipientEntityId?: string;

  @IsString()
  @IsNotEmpty()
  @MaxLength(255)
  recipientDisplayName: string;

  @IsOptional()
  @IsString()
  @MaxLength(255)
  recipientRole?: string;

  @IsOptional()
  @IsString()
  @MaxLength(500)
  subject?: string;
}
