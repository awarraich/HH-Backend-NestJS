import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
} from 'typeorm';
import { Organization } from '../../entities/organization.entity';

/** Stored gallery item: either file_path (backend upload) or url (external). */
export type GalleryItemStored = {
  id: string;
  file_path?: string;
  url?: string;
  caption: string;
  category: string;
};

/** Stored video item: either file_path (backend upload) or url (external). thumbnail can be url or path. */
export type VideoItemStored = {
  id: string;
  file_path?: string;
  url?: string;
  title: string;
  thumbnail?: string;
  description?: string;
  duration?: string;
  category?: string;
};

@Entity('organization_company_profiles')
@Index(['organization_id'], { unique: true })
export class OrganizationCompanyProfile {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid', unique: true })
  organization_id: string;

  @Column({ type: 'varchar', length: 255, nullable: true })
  company_name: string | null;

  @Column({ type: 'varchar', length: 500, nullable: true })
  logo: string | null;

  @Column({ type: 'varchar', length: 500, nullable: true })
  cover_image: string | null;

  /** Banner carousel: up to 3 image URLs/paths. When set, cover_image is kept in sync with first. */
  @Column({ type: 'jsonb', nullable: true, default: '[]' })
  cover_images: string[];

  @Column({ type: 'varchar', length: 50, nullable: true })
  organization_type: string | null;

  @Column({ type: 'text', nullable: true })
  description: string | null;

  @Column({ type: 'varchar', length: 50, nullable: true })
  phone: string | null;

  @Column({ type: 'varchar', length: 255, nullable: true })
  email: string | null;

  @Column({ type: 'varchar', length: 50, nullable: true })
  fax: string | null;

  @Column({ type: 'varchar', length: 500, nullable: true })
  website: string | null;

  @Column({ type: 'varchar', length: 500, nullable: true })
  address: string | null;

  @Column({ type: 'jsonb', nullable: true })
  business_hours: Record<string, { open: string; close: string; closed: boolean }> | null;

  @Column({ type: 'jsonb', nullable: true })
  service_area: string[] | null;

  @Column({ type: 'varchar', length: 100, nullable: true })
  coverage_radius: string | null;

  @Column({ type: 'jsonb', nullable: true })
  selected_services: string[] | null;

  @Column({ type: 'jsonb', nullable: true })
  licenses: string[] | null;

  @Column({ type: 'jsonb', nullable: true })
  certifications: string[] | null;

  /** Gallery: array of { id, file_path?, url?, caption, category } */
  @Column({ type: 'jsonb', nullable: true, default: '[]' })
  gallery: GalleryItemStored[];

  /** Videos: array of { id, file_path?, url?, title, thumbnail?, description?, duration?, category? } */
  @Column({ type: 'jsonb', nullable: true, default: '[]' })
  videos: VideoItemStored[];

  @Column({ type: 'jsonb', nullable: true, default: '[]' })
  packages: Array<{
    id: string;
    name: string;
    description: string;
    price: string;
    features?: string[];
  }>;

  @Column({ type: 'jsonb', nullable: true })
  specialty_services: string[] | null;

  @Column({ type: 'jsonb', nullable: true })
  accepted_insurance: string[] | null;

  /** Amenities: array of { name, image_url?, price? }. Legacy DB may have string[]; normalize when reading. */
  @Column({ type: 'jsonb', nullable: true })
  amenities: Array<{ name: string; image_url?: string; price?: string }> | string[] | null;

  @Column({ type: 'jsonb', nullable: true })
  room_types: string[] | null;

  @Column({ type: 'jsonb', nullable: true })
  equipment_catalog: string[] | null;

  @Column({ type: 'jsonb', nullable: true })
  transport_types: string[] | null;

  @Column({ type: 'varchar', length: 20, nullable: true })
  availability_status: string | null;

  @Column({ type: 'decimal', precision: 3, scale: 2, nullable: true })
  rating: number | null;

  @Column({ type: 'integer', nullable: true })
  review_count: number | null;

  @Column({ type: 'jsonb', nullable: true, default: '[]' })
  reviews: Array<{
    id: string;
    author: string;
    rating: number;
    text: string;
    date: string;
    reply?: string;
    replied_at?: string;
  }>;

  @CreateDateColumn({ type: 'timestamp with time zone', default: () => 'NOW()' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamp with time zone', default: () => 'NOW()' })
  updated_at: Date;

  @ManyToOne(() => Organization, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'organization_id' })
  organization: Organization;
}
