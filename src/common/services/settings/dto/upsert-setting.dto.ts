import {
  IsIn,
  IsOptional,
  IsString,
  IsUUID,
  ValidateIf,
  IsDefined,
  MaxLength,
} from 'class-validator';

export const SETTING_SCOPES = ['global', 'organization'] as const;
export type SettingScope = (typeof SETTING_SCOPES)[number];

export class UpsertSettingDto {
  @IsIn(SETTING_SCOPES)
  scope: SettingScope;

  @ValidateIf((o: UpsertSettingDto) => o.scope === 'organization')
  @IsUUID()
  organizationId?: string;

  @IsDefined()
  value: unknown;

  @IsOptional()
  @IsString()
  @MaxLength(500)
  description?: string;
}
