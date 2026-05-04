import { IsString, IsNotEmpty, MaxLength, Matches } from 'class-validator';

export class EnableGoogleChatDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(255)
  @Matches(/^[a-z0-9.-]+\.[a-z]{2,}$/i, {
    message: 'workspace_domain must be a valid domain (e.g. guardianhha.com)',
  })
  workspace_domain: string;
}
