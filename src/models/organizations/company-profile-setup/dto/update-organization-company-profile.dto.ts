import {
  IsString,
  IsOptional,
  IsArray,
  IsObject,
  IsNumber,
  MaxLength,
  Min,
  Max,
} from 'class-validator';

/** Partial update: all fields optional. */
export class UpdateOrganizationCompanyProfileDto {
  @IsOptional()
  @IsString()
  @MaxLength(255)
  company_name?: string;

  @IsOptional()
  @IsString()
  @MaxLength(500)
  logo?: string;

  @IsOptional()
  @IsString()
  @MaxLength(500)
  cover_image?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  organization_type?: string;

  @IsOptional()
  @IsString()
  description?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  phone?: string;

  @IsOptional()
  @IsString()
  @MaxLength(255)
  email?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  fax?: string;

  @IsOptional()
  @IsString()
  @MaxLength(500)
  website?: string;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  cover_images?: string[];

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
  @MaxLength(100)
  city?: string;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  state?: string;

  @IsOptional()
  @IsString()
  @MaxLength(20)
  zip_code?: string;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  country?: string;

  @IsOptional()
  @IsObject()
  business_hours?: Record<string, { open: string; close: string; closed: boolean }>;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  service_area?: string[];

  @IsOptional()
  @IsString()
  @MaxLength(100)
  coverage_radius?: string;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  selected_services?: string[];

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  licenses?: string[];

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  certifications?: string[];

  @IsOptional()
  @IsArray()
  gallery?: Array<{ id: string; url?: string; caption?: string; category?: string }>;

  @IsOptional()
  @IsArray()
  videos?: Array<{
    id: string;
    url?: string;
    title: string;
    thumbnail?: string;
    description?: string;
    duration?: string;
    category?: string;
  }>;

  @IsOptional()
  @IsArray()
  packages?: Array<{
    id: string;
    name: string;
    description: string;
    price: string;
    features?: string[];
  }>;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  specialty_services?: string[];

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  accepted_insurance?: string[];

  @IsOptional()
  @IsArray()
  amenities?: Array<{ name?: string; image_url?: string; price?: string }>;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  room_types?: string[];

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  equipment_catalog?: string[];

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  transport_types?: string[];

  @IsOptional()
  @IsString()
  @MaxLength(20)
  availability_status?: string;

  @IsOptional()
  @IsNumber()
  @Min(0)
  @Max(5)
  rating?: number;

  @IsOptional()
  @IsNumber()
  @Min(0)
  review_count?: number;

  @IsOptional()
  @IsArray()
  reviews?: Array<{
    id: string;
    author: string;
    rating: number;
    text: string;
    date: string;
    reply?: string;
    replied_at?: string;
  }>;
}
