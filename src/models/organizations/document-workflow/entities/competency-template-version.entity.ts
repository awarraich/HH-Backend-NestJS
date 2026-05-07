import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
  CreateDateColumn,
  Index,
  Unique,
} from 'typeorm';
import { CompetencyTemplate } from './competency-template.entity';

/**
 * Frozen, append-only snapshot of a `competency_templates` row at the
 * moment its admin clicked "Publish". Source of truth for any code path
 * that needs to know "what did this template look like when the user
 * filled it" — the parent `competency_templates` row stays mutable
 * (drafts), but every assignment + saved value is pinned to a version
 * here so historical answers always render against the schema the user
 * actually saw.
 *
 * The whole template payload (`document_fields`, `roles`, `pdf_*`) is
 * snapshotted at publish time, even though some of that payload could
 * theoretically be derived later by joining the parent — denormalizing
 * is the only way to guarantee historical fidelity once the parent
 * draft has moved on.
 *
 * `version_number` is monotonic per template (1, 2, 3, …). The unique
 * index on (template_id, version_number) prevents accidental gaps or
 * duplicates when two admins click Publish at the same time — the
 * second insert fails and the service retries with a higher number.
 */
@Entity('competency_template_versions')
@Index(['template_id'])
@Unique(['template_id', 'version_number'])
export class CompetencyTemplateVersion {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  template_id: string;

  @Column({ type: 'int' })
  version_number: number;

  @Column({ type: 'jsonb', default: () => "'[]'" })
  document_fields: Record<string, unknown>[];

  @Column({ type: 'jsonb', default: () => "'[]'" })
  roles: Record<string, unknown>[];

  @Column({ type: 'varchar', length: 500, nullable: true })
  pdf_file_key: string | null;

  @Column({ type: 'varchar', length: 255, nullable: true })
  pdf_original_name: string | null;

  @Column({ type: 'integer', nullable: true })
  pdf_size_bytes: number | null;

  @CreateDateColumn({ type: 'timestamptz', default: () => 'now()' })
  published_at: Date;

  @Column({ type: 'uuid', nullable: true })
  published_by: string | null;

  @ManyToOne(() => CompetencyTemplate, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'template_id' })
  template: CompetencyTemplate;
}
