import { IsUUID, IsArray, ValidateNested, IsString, IsNotEmpty } from 'class-validator';
import { Type } from 'class-transformer';

export class FieldValueItem {
  @IsString()
  @IsNotEmpty()
  fieldId: string;

  @IsNotEmpty()
  value: any;
}

export class SubmitExternalFieldsDto {
  @IsUUID()
  userId: string;

  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => FieldValueItem)
  fields: FieldValueItem[];
}
