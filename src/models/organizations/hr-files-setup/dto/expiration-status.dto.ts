import { IsArray, IsUUID } from 'class-validator';

export class ExpirationStatusDto {
  @IsArray()
  @IsUUID('4', { each: true })
  document_ids: string[];
}
