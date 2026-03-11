import { IsString, IsNotEmpty, IsOptional, IsArray, IsUUID, ValidateNested } from 'class-validator';
import { Type } from 'class-transformer';

export class ChatMessageDto {
  @IsString()
  role!: 'user' | 'assistant';

  @IsString()
  content!: string;
}

export class EmployeeDocumentsChatRequestDto {
  @IsString()
  @IsNotEmpty()
  message!: string;

  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => ChatMessageDto)
  history?: ChatMessageDto[];

  /** When set, chat is restricted to this document only (org/employee from URL). */
  @IsOptional()
  @IsUUID('4')
  document_id?: string;
}
