import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
} from 'typeorm';

@Entity('competency_templates')
@Index(['organization_id'])
export class CompetencyTemplate {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  organization_id: string;

  @Column({ type: 'varchar', length: 255, default: '' })
  name: string;

  @Column({ type: 'text', default: '' })
  description: string;

  @Column({ type: 'jsonb', default: [] })
  document_fields: Record<string, any>[];

  @Column({ type: 'jsonb', default: [] })
  roles: Record<string, any>[];

  @Column({ type: 'varchar', length: 500, nullable: true })
  pdf_file_key: string | null;

  @Column({ type: 'varchar', length: 255, nullable: true })
  pdf_original_name: string | null;

  @Column({ type: 'integer', nullable: true })
  pdf_size_bytes: number | null;

  @Column({ type: 'uuid', nullable: true })
  created_by: string | null;

  /**
   * What this template is used for — separates the original Document
   * Templates flow from Job Application Forms so each tab in the Document
   * Workflow page can filter its own list. `'document'` (default) means a
   * competency / onboarding / signable document; `'applicant_form'` means a
   * PDF an applicant fills when applying for a job.
   */
  @Column({ type: 'varchar', length: 32, default: 'document' })
  purpose: 'document' | 'applicant_form';

  @CreateDateColumn({ type: 'timestamptz', default: () => 'now()' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamptz', default: () => 'now()' })
  updated_at: Date;
}
