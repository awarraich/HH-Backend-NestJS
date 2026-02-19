import {
  IsString,
  IsNotEmpty,
  IsEmail,
  IsUUID,
  IsArray,
  ArrayMinSize,
  IsOptional,
  MaxLength,
} from 'class-validator';

export class CreateOrganizationStaffDto {
  @IsNotEmpty()
  @IsEmail()
  email: string;

  @IsNotEmpty()
  @IsString()
  @MaxLength(255)
  firstName: string;

  @IsNotEmpty()
  @IsString()
  @MaxLength(255)
  lastName: string;

  @IsArray()
  @ArrayMinSize(1, { message: 'At least one staff role is required' })
  @IsUUID('4', { each: true })
  staff_role_ids: string[];

  @IsOptional()
  @IsString()
  @MaxLength(100)
  department?: string;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  position_title?: string;
}
