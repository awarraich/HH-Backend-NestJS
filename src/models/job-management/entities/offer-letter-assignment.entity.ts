import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  ManyToOne,
  JoinColumn,
  OneToMany,
  Index,
} from 'typeorm';
import { JobApplication } from './job-application.entity';
import { CompetencyTemplate } from '../../organizations/document-workflow/entities/competency-template.entity';
import { OfferLetterAssignmentRole } from './offer-letter-assignment-role.entity';
import { OfferLetterFieldValue } from './offer-letter-field-value.entity';

export type OfferLetterAssignmentStatus =
  | 'draft'
  | 'sent'
  | 'in_progress'
  | 'completed'
  | 'voided';

/**
 * A single Document-Workflow template instantiated for one Job Application.
 *
 * Each offer gets its own row with a frozen template snapshot so that later
 * edits to the source template never mutate an outstanding offer letter.
 */
@Entity('offer_letter_assignments')
@Index(['organization_id'])
@Index(['job_application_id'])
@Index(['template_id'])
@Index(['organization_id', 'status'])
export class OfferLetterAssignment {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  organization_id: string;

  @Column({ type: 'uuid' })
  job_application_id: string;

  @Column({ type: 'uuid' })
  template_id: string;

  /** Frozen snapshot of CompetencyTemplate (name, roles, documentFields, pdf metadata). */
  @Column({ type: 'jsonb' })
  template_snapshot: Record<string, unknown>;

  @Column({ type: 'varchar', length: 20, default: 'draft' })
  status: OfferLetterAssignmentStatus;

  @Column({ type: 'timestamptz', nullable: true })
  sent_at: Date | null;

  @Column({ type: 'timestamptz', nullable: true })
  completed_at: Date | null;

  @Column({ type: 'uuid', nullable: true })
  created_by: string | null;

  @CreateDateColumn({ type: 'timestamptz' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamptz' })
  updated_at: Date;

  @ManyToOne(() => JobApplication, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'job_application_id' })
  jobApplication: JobApplication;

  @ManyToOne(() => CompetencyTemplate, { onDelete: 'RESTRICT' })
  @JoinColumn({ name: 'template_id' })
  template: CompetencyTemplate;

  @OneToMany(() => OfferLetterAssignmentRole, (r) => r.assignment, { cascade: true })
  roleAssignments: OfferLetterAssignmentRole[];

  @OneToMany(() => OfferLetterFieldValue, (v) => v.assignment, { cascade: true })
  fieldValues: OfferLetterFieldValue[];
}
