import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
  CreateDateColumn,
  UpdateDateColumn,
  OneToMany,
  Index,
} from 'typeorm';
import { Organization } from '../../entities/organization.entity';
import { OrganizationDocumentCategory } from './organization-document-category.entity';
import { User } from '../../../../authentication/entities/user.entity';
import { OrganizationDocumentChunk } from './organization-document-chunk.entity';

@Entity('organization_documents')
@Index(['organization_id'])
@Index(['category_id'])
@Index(['organization_id', 'category_id'])
export class OrganizationDocument {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  organization_id: string;

  @Column({ type: 'uuid' })
  category_id: string;

  @Column({ type: 'varchar', length: 255 })
  document_name: string;

  @Column({ type: 'varchar', length: 255 })
  file_name: string;

  @Column({ type: 'varchar', length: 500 })
  file_path: string;

  @Column({ type: 'bigint', nullable: true })
  file_size_bytes: number | null;

  @Column({ type: 'varchar', length: 100, nullable: true })
  mime_type: string | null;

  @Column({ type: 'boolean', default: false })
  is_required: boolean;

  @Column({ type: 'boolean', default: false })
  has_expiration: boolean;

  @Column({ type: 'date', nullable: true })
  expiration_date: Date | null;

  @Column({ type: 'integer', default: 90 })
  expiration_reminder_days: number;

  @Column({ type: 'text', nullable: true })
  extracted_text: string | null;

  @Column({ type: 'varchar', length: 20, default: 'pending' })
  extraction_status: string;

  @Column({ type: 'text', nullable: true })
  extraction_error: string | null;

  @Column({ type: 'uuid', nullable: true })
  uploaded_by: string | null;

  @Column({ type: 'uuid', nullable: true })
  created_by: string | null;

  @Column({ type: 'uuid', nullable: true })
  updated_by: string | null;

  @CreateDateColumn({ type: 'timestamp with time zone', default: () => 'NOW()' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamp with time zone', default: () => 'NOW()' })
  updated_at: Date;

  @Column({ type: 'timestamp with time zone', nullable: true })
  deleted_at: Date | null;

  @ManyToOne(() => Organization, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'organization_id' })
  organization: Organization;

  @ManyToOne(() => OrganizationDocumentCategory, { onDelete: 'RESTRICT' })
  @JoinColumn({ name: 'category_id' })
  category: OrganizationDocumentCategory;

  @ManyToOne(() => User, { onDelete: 'SET NULL' })
  @JoinColumn({ name: 'uploaded_by' })
  uploadedByUser: User | null;

  @OneToMany(() => OrganizationDocumentChunk, (chunk) => chunk.document)
  chunks: OrganizationDocumentChunk[];
}
