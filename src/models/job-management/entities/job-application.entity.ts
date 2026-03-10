import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  ManyToOne,
  JoinColumn,
  Index,
} from 'typeorm';
import { JobPosting } from './job-posting.entity';

@Entity('job_applications')
@Index(['job_posting_id'])
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
  status: string; // pending | not_seen | interview | offer_sent | rejected | etc.

  @CreateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;

  @ManyToOne(() => JobPosting, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'job_posting_id' })
  job_posting: JobPosting;
}
