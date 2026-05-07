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
import { CompetencyAssignment } from './competency-assignment.entity';
import { DocumentWorkflowRole } from './document-workflow-role.entity';

export type CompetencyRecipientType =
  | 'supervisor'
  | 'employee'
  | 'external_employee';

export type CompetencyAssignmentRoleStatus =
  | 'pending'
  | 'in_progress'
  | 'submitted';

/**
 * One row per (competency_assignment, role, user). Drives:
 *   - email fan-out at create time (one email per row),
 *   - per-role authorisation on the v2 fill / submit endpoints,
 *   - per-role status badges in the org-side panel.
 *
 * `recipient_type` tells the email layer where the deep-link points:
 *   - supervisor         → Document Workflow → Assignments tab
 *   - employee           → Employee → HR Files → Competency tab
 *   - external_employee  → token-gated public /competency/fill/:token page
 */
@Entity('competency_assignment_roles')
@Index(['assignment_id'])
@Index(['user_id'])
@Index(['fill_token'])
@Unique(['assignment_id', 'role_id', 'user_id'])
export class CompetencyAssignmentRole {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  assignment_id: string;

  @Column({ type: 'uuid' })
  role_id: string;

  @Column({ type: 'uuid' })
  user_id: string;

  @Column({ type: 'varchar', length: 32 })
  recipient_type: CompetencyRecipientType;

  @Column({ type: 'varchar', length: 20, default: 'pending' })
  status: CompetencyAssignmentRoleStatus;

  @Column({ type: 'timestamptz', nullable: true })
  submitted_at: Date | null;

  /** One-time opaque token used by external employees. */
  @Column({ type: 'varchar', length: 128, nullable: true, unique: true })
  fill_token: string | null;

  @Column({ type: 'timestamptz', nullable: true })
  fill_token_expires_at: Date | null;

  @CreateDateColumn({ type: 'timestamptz' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamptz' })
  updated_at: Date;

  @ManyToOne(() => CompetencyAssignment, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'assignment_id' })
  assignment: CompetencyAssignment;

  @ManyToOne(() => DocumentWorkflowRole, { onDelete: 'RESTRICT' })
  @JoinColumn({ name: 'role_id' })
  role: DocumentWorkflowRole;
}
