import { IsIn, IsOptional, IsUUID, ValidateIf } from 'class-validator';
import { SETTING_SCOPES, type SettingScope } from './upsert-setting.dto';

export const LLM_PROVIDERS = ['openai', 'bedrock'] as const;
export type LlmProviderName = (typeof LLM_PROVIDERS)[number];

export class SetLlmProviderDto {
  @IsIn(SETTING_SCOPES)
  scope: SettingScope;

  @ValidateIf((o: SetLlmProviderDto) => o.scope === 'organization')
  @IsUUID()
  organizationId?: string;

  @IsIn(LLM_PROVIDERS)
  provider: LlmProviderName;
}

export class DeleteLlmProviderQueryDto {
  @IsIn(SETTING_SCOPES)
  scope: SettingScope;

  @ValidateIf((o: DeleteLlmProviderQueryDto) => o.scope === 'organization')
  @IsUUID()
  organizationId?: string;
}

export class GetSettingsQueryDto {
  @IsOptional()
  @IsUUID()
  organizationId?: string;
}
