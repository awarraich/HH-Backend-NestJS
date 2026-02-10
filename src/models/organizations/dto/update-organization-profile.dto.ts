import {
  IsString,
  IsOptional,
  IsDateString,
  MaxLength,
  Matches,
} from 'class-validator';

export class UpdateOrganizationProfileDto {
  @IsOptional()
  @IsString()
  @MaxLength(255)
  address_line_1?: string;

  @IsOptional()
  @IsString()
  @MaxLength(255)
  address_line_2?: string;

  @IsOptional()
  @IsString()
  @MaxLength(4)
  zip_code_1?: string;

  @IsOptional()
  @IsString()
  @MaxLength(4)
  zip_code_2?: string;

  @IsOptional()
  @IsString()
  @MaxLength(20)
  phone_number?: string;

  @IsOptional()
  @IsString()
  @MaxLength(20)
  fax_number?: string;

  @IsOptional()
  @IsString()
  @MaxLength(10)
  npi_number?: string;

  @IsOptional()
  @IsString()
  @MaxLength(9)
  ein?: string;

  @IsOptional()
  @IsString()
  @MaxLength(9)
  ptin?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  state_license?: string;

  @IsOptional()
  @IsDateString()
  state_license_expiration?: string;

  @IsOptional()
  @IsString()
  clia_number?: string;

  @IsOptional()
  @IsDateString()
  clia_expiration?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  business_license?: string;

  @IsOptional()
  @IsDateString()
  business_license_expiration?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  ftb?: string;

  // Personnel fields
  @IsOptional()
  @IsString()
  @MaxLength(255)
  administrator_name?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  administrator_id?: string;

  @IsOptional()
  @IsDateString()
  administrator_expiration?: string;

  @IsOptional()
  @IsString()
  @MaxLength(255)
  designee_administrator_name?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  designee_administrator_id?: string;

  @IsOptional()
  @IsDateString()
  designee_administrator_expiration?: string;

  @IsOptional()
  @IsString()
  @MaxLength(255)
  dpcs_don_name?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  dpcs_don_id?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  dpcs_don_license?: string;

  @IsOptional()
  @IsDateString()
  dpcs_don_expiration?: string;

  @IsOptional()
  @IsString()
  @MaxLength(255)
  designee_dpcs_don_name?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  designee_dpcs_don_id?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  designee_dpcs_don_license?: string;

  @IsOptional()
  @IsDateString()
  designee_dpcs_don_expiration?: string;

  @IsOptional()
  @IsString()
  @MaxLength(255)
  medical_director_name?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  medical_director_id?: string;

  @IsOptional()
  @IsDateString()
  medical_director_expiration?: string;

  // Board and Care specific
  @IsOptional()
  @IsString()
  @MaxLength(255)
  admin_name?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  admin_license?: string;

  @IsOptional()
  @IsDateString()
  admin_expiration?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  rcfe_number?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  rcfe_license?: string;

  @IsOptional()
  @IsDateString()
  rcfe_expiration?: string;

  // Pharmacist specific
  @IsOptional()
  @IsString()
  @MaxLength(255)
  pharmacist_name?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  pharmacist_license?: string;

  @IsOptional()
  @IsDateString()
  pharmacist_license_expiration?: string;

  // Lab specific
  @IsOptional()
  @IsString()
  @MaxLength(255)
  lab_owner_name?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  lab_license?: string;

  @IsOptional()
  @IsDateString()
  lab_license_expiration?: string;
}

