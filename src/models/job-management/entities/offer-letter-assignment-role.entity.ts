import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  ManyToOne,
  JoinColumn,
  Index,
  Unique,
} from 'typeorm';
import { OfferLetterAssignment } from './offer-letter-assignment.entity';
import { DocumentWorkflowRole } from '../../organizations/document-workflow/entities/document-workflow-role.entity';

/**
 * Who fills which template role for a given offer letter assignment.
 *
 * `recipient_type` drives where the document surfaces for the filler:
 *   - supervisor         → Document Workflow → Assignment tab
 *   - employee           → Offer Letter tab inside the employee's Job tab
 *   - external_employee  → token-gated public /offer-letter/fill/:token page
 */
export type OfferRecipientType = 'supervisor' | 'employee' | 'external_employee';

@Entity('offer_letter_assignment_roles')
@Index(['assignment_id'])
@Index(['user_id'])
@Index(['fill_token'])
@Unique(['assignment_id', 'role_id', 'user_id'])
export class OfferLetterAssignmentRole {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  assignment_id: string;

  @Column({ type: 'uuid' })
  role_id: string;

  @Column({ type: 'uuid' })
  user_id: string;

  @Column({ type: 'varchar', length: 32 })
  recipient_type: OfferRecipientType;

  /** One-time opaque token used by external employees (and optionally emailed). */
  @Column({ type: 'varchar', length: 128, nullable: true, unique: true })
  fill_token: string | null;

  @Column({ type: 'timestamptz', nullable: true })
  fill_token_expires_at: Date | null;

  @Column({ type: 'timestamptz', nullable: true })
  completed_at: Date | null;

  @CreateDateColumn({ type: 'timestamptz' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamptz' })
  updated_at: Date;

  @ManyToOne(() => OfferLetterAssignment, (a) => a.roleAssignments, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'assignment_id' })
  assignment: OfferLetterAssignment;

  @ManyToOne(() => DocumentWorkflowRole, { onDelete: 'RESTRICT' })
  @JoinColumn({ name: 'role_id' })
  role: DocumentWorkflowRole;
}
