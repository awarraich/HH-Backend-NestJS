import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { JobApplication } from './job-application.entity';

@Entity('offer_letter_signing_tokens')
@Index(['expires_at'])
export class OfferLetterSigningToken {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'varchar', length: 128, unique: true })
  @Index({ unique: true })
  token: string;

  @Column({ type: 'uuid' })
  job_application_id: string;

  @Column({ type: 'varchar', length: 255 })
  candidate_email: string;

  @Column({ type: 'varchar', length: 255 })
  candidate_name: string;

  @Column({ type: 'varchar', length: 500 })
  job_title: string;

  @Column({ type: 'uuid' })
  organization_id: string;

  @Column({ type: 'varchar', length: 2048 })
  pdf_url: string;

  /** { pageNumber, x, y, width, height } in PDF point coordinates (origin top-left). */
  @Column({ type: 'jsonb', nullable: true })
  signature_position: Record<string, unknown> | null;

  @Column({ type: 'timestamp' })
  expires_at: Date;

  @Column({ type: 'timestamp', nullable: true })
  used_at: Date | null;

  @Column({ type: 'varchar', length: 2048, nullable: true })
  signed_pdf_url: string | null;

  @Column({ type: 'jsonb', nullable: true })
  audit_trail: Record<string, unknown> | null;

  @CreateDateColumn()
  created_at: Date;

  @ManyToOne(() => JobApplication, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'job_application_id' })
  job_application: JobApplication;
}
