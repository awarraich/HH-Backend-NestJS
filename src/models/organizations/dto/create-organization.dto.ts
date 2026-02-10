import {
  IsString,
  IsNotEmpty,
  IsOptional,
  MaxLength,
  Matches,
} from 'class-validator';

export class CreateOrganizationDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(255)
  organization_name: string;

  @IsString()
  @IsOptional()
  @MaxLength(20)
  tax_id?: string;

  @IsString()
  @IsOptional()
  @MaxLength(50)
  registration_number?: string;

  @IsString()
  @IsOptional()
  @MaxLength(200)
  @Matches(/^https?:\/\/.+/, {
    message: 'Website must be a valid URL starting with http:// or https://',
  })
  website?: string;

  @IsString()
  @IsOptional()
  description?: string;
}

