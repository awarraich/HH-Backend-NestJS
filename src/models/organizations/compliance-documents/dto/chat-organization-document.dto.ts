import {
  IsString,
  IsNotEmpty,
  IsOptional,
  IsArray,
  IsUUID,
  IsIn,
  ValidateNested,
} from 'class-validator';
import { Type } from 'class-transformer';

class ChatHistoryItemDto {
  @IsIn(['user', 'assistant'])
  role: 'user' | 'assistant';

  @IsString()
  @IsNotEmpty()
  content: string;
}

export class ChatOrganizationDocumentDto {
  @IsString()
  @IsNotEmpty()
  message: string;

  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => ChatHistoryItemDto)
  @IsOptional()
  history?: ChatHistoryItemDto[];

  @IsArray()
  @IsUUID('4', { each: true })
  @IsOptional()
  document_ids?: string[];
}
