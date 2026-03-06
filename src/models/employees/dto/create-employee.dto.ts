import {
  IsString,
  IsNotEmpty,
  IsOptional,
  IsUUID,
  IsDateString,
  MaxLength,
  IsIn,
  IsArray,
} from 'class-validator';

export class CreateEmployeeDto {
  @IsNotEmpty()
  @IsUUID()
  user_id: string;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  department?: string;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  position_title?: string;

  @IsOptional()
  @IsDateString()
  start_date?: string;

  @IsOptional()
  @IsDateString()
  end_date?: string;

  @IsOptional()
  @IsString()
  @IsIn(['FULL_TIME', 'PART_TIME', 'CONTRACT', 'PER_DIEM'])
  @MaxLength(20)
  employment_type?: string;

  @IsOptional()
  @IsString()
  notes?: string;

  @IsOptional()
  @IsUUID()
  provider_role_id?: string;

  @IsOptional()
  @IsArray()
  @IsUUID('4', { each: true })
  requirement_tag_ids?: string[];
}
