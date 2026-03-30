import { IsObject } from 'class-validator';

export class FillAssignmentDto {
  @IsObject()
  fieldValues: Record<string, string>;
}
