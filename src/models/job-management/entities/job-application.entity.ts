import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  ManyToOne,
  JoinColumn,
  Index,
  OneToMany,
} from 'typeorm';
import { JobPosting } from './job-posting.entity';
import { JobApplicationFieldValue } from './job-application-field-value.entity';

@Entity('job_applications')
@Index(['job_posting_id'])
// Composite indexes to keep the paginated /organization/:id/job-applications list fast
// even as the table grows (filters: status bucket, sort: created_at DESC).
@Index(['job_posting_id', 'status', 'created_at'])
@Index(['status', 'created_at'])
export class JobApplication {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  job_posting_id: string;

  @Column({ type: 'varchar', length: 255 })
  applicant_name: string;

  @Column({ type: 'varchar', length: 255 })
  applicant_email: string;

  @Column({ type: 'varchar', length: 50, nullable: true })
  applicant_phone: string | null;

  @Column({ type: 'text', nullable: true })
  notes: string | null;

  /** Application form field answers (key-value) */
  @Column({ type: 'jsonb', nullable: true })
  submitted_fields: Record<string, unknown> | null;

  @Column({ type: 'varchar', length: 50, default: 'pending' })
  status: string;

  @Column({ type: 'jsonb', nullable: true })
  offer_details: Record<string, unknown> | null;

  /** Interview schedule captured when HR books the interview (date/time/mode/location/message). */
  @Column({ type: 'jsonb', nullable: true })
  interview_details: Record<string, unknown> | null;

  /** Reason the candidate gave when declining an offer. Populated when status = offer_declined. */
  @Column({ type: 'text', nullable: true })
  decline_reason: string | null;

  @CreateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;

  @ManyToOne(() => JobPosting, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'job_posting_id' })
  job_posting: JobPosting;

  /** Normalized per-field answers. The JSONB `submitted_fields` column stays populated for
   *  backwards compatibility during the transition but is derived from these rows. */
  @OneToMany(() => JobApplicationFieldValue, (v) => v.application, { cascade: true })
  field_values: JobApplicationFieldValue[];
}
