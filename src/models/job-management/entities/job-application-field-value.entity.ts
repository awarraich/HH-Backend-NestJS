import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  ManyToOne,
  JoinColumn,
  Index,
} from 'typeorm';
import { JobApplication } from './job-application.entity';

/**
 * Normalized row for a single form-field answer on a job application.
 *
 * Replaces the monolithic `job_applications.submitted_fields` JSONB so each answer is
 * queryable/indexable independently and belongs to the HR-side schema rather than a
 * single blob mixed with applicant-controlled data.
 *
 * Field identity:
 *   - `field_key`     — stable machine id (e.g. "resume" or "field_1773877150370_rcvm7ky").
 *   - `field_label`   — human-readable label captured at submission time so legacy
 *                       applications still render sensibly after form edits.
 *
 * Value storage:
 *   - `value_text`    — plain strings (names, phone numbers, short text).
 *   - `value_json`    — structured values (file refs `{file_url, file_name}`,
 *                       array fields like experiences/references, nested objects).
 *
 * For any given row exactly one of `value_text` / `value_json` is typically set.
 */
@Entity('job_application_field_values')
@Index(['application_id'])
@Index(['application_id', 'field_key'], { unique: true })
export class JobApplicationFieldValue {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  application_id: string;

  @Column({ type: 'varchar', length: 255 })
  field_key: string;

  @Column({ type: 'varchar', length: 500, nullable: true })
  field_label: string | null;

  @Column({ type: 'text', nullable: true })
  value_text: string | null;

  @Column({ type: 'jsonb', nullable: true })
  value_json: unknown | null;

  @CreateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;

  @UpdateDateColumn({
    type: 'timestamp',
    default: () => 'CURRENT_TIMESTAMP',
    onUpdate: 'CURRENT_TIMESTAMP',
  })
  updated_at: Date;

  @ManyToOne(() => JobApplication, (ja) => ja.field_values, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'application_id' })
  application: JobApplication;
}
