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

  /**
   * Whether assignments of this template require an admin review step
   * after the employee fills it. When false (default), an assignment
   * goes pending → in_progress → completed and stops there. When true,
   * the employee must explicitly /submit, an admin must /approve or
   * /reject, and the lifecycle gains 'submitted' / 'approved' /
   * 'rejected' states. Used for compliance-sensitive forms (I-9,
   * onboarding attestations) where someone in HR must sign off before
   * the document is treated as binding.
   */
  @Column({ type: 'boolean', default: false })
  requires_review: boolean;

  /**
   * Pointer to the most-recently published `competency_template_versions`
   * row. New assignments freeze on this version at assign time. The
   * fields here on the parent (`document_fields`, `roles`, `pdf_*`) are
   * the editable DRAFT — they don't affect existing assignments until
   * the admin publishes a new version. Null only during the brief
   * window between create and the auto-publish of v1, or for legacy
   * rows pre-Phase-3 backfill.
   */
  @Column({ type: 'uuid', nullable: true })
  current_version_id: string | null;

  @CreateDateColumn({ type: 'timestamptz', default: () => 'now()' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamptz', default: () => 'now()' })
  updated_at: Date;
}
