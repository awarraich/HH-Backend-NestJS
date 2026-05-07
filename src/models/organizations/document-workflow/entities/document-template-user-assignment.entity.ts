import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  Index,
  Unique,
  ManyToOne,
  JoinColumn,
} from 'typeorm';
import { CompetencyTemplate } from './competency-template.entity';
import { DocumentWorkflowRole } from './document-workflow-role.entity';

@Entity('document_template_user_assignments')
@Index(['template_id'])
@Index(['user_id'])
@Index(['template_id', 'user_id'])
@Index(['user_id', 'status'])
@Unique(['template_id', 'user_id', 'role_id'])
export class DocumentTemplateUserAssignment {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  template_id: string;

  /**
   * The frozen template snapshot this assignment was created against.
   * Pinned at assign time and never mutated; an admin republishing the
   * template won't change this value. Read paths must dereference fields
   * via this version, not via the live `competency_templates` row, so
   * historical answers stay interpretable forever.
   */
  @Column({ type: 'uuid' })
  template_version_id: string;

  @Column({ type: 'uuid' })
  user_id: string;

  @Column({ type: 'uuid' })
  role_id: string;

  @Column({ type: 'uuid', nullable: true })
  assigned_by: string | null;

  /**
   * Lifecycle status of this assignment, denormalized from
   * document_field_values so the HR File / Needs Action queries can
   * filter by status directly instead of recomputing "filled vs required"
   * per render. Recomputed by `submitFields` after each value save.
   *
   * Values:
   *   'pending'     — no fields saved yet (default for new rows)
   *   'in_progress' — some required fields saved, not all
   *   'completed'   — all required fields saved
   *   'submitted' / 'approved' / 'rejected' — reserved for Phase 2.
   */
  @Column({ type: 'varchar', length: 32, default: 'pending' })
  status: string;

  /** Wall-clock time of the first saved field value. Set on the
   *  pending → in_progress transition; never reset. */
  @Column({ type: 'timestamptz', nullable: true })
  started_at: Date | null;

  /** Wall-clock time of the in_progress → completed transition. Cleared
   *  if an admin reopens the assignment (Phase 2 lifecycle). */
  @Column({ type: 'timestamptz', nullable: true })
  completed_at: Date | null;

  /** When the employee explicitly submitted the assignment for review.
   *  Only populated when the template has `requires_review = true` —
   *  the auto-`completed` state is terminal otherwise. */
  @Column({ type: 'timestamptz', nullable: true })
  submitted_at: Date | null;

  /** Usually equal to `user_id` (the assignee submitted on their own
   *  behalf), but kept distinct so HR can submit on behalf of an
   *  employee in extraordinary cases without losing audit fidelity. */
  @Column({ type: 'uuid', nullable: true })
  submitted_by: string | null;

  /** When the admin approved or rejected the submission. */
  @Column({ type: 'timestamptz', nullable: true })
  reviewed_at: Date | null;

  /** Admin user who reviewed (approved or rejected) the submission. */
  @Column({ type: 'uuid', nullable: true })
  reviewed_by: string | null;

  /** Free-text reason supplied with a rejection so the employee knows
   *  what to fix. Cleared when the assignment is reopened or
   *  re-approved. */
  @Column({ type: 'text', nullable: true })
  rejection_reason: string | null;

  @CreateDateColumn({ type: 'timestamptz', default: () => 'now()' })
  created_at: Date;

  @ManyToOne(() => CompetencyTemplate, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'template_id' })
  template: CompetencyTemplate;

  @ManyToOne(() => DocumentWorkflowRole, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'role_id' })
  role: DocumentWorkflowRole;
}
