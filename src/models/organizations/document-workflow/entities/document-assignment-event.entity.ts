import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  ManyToOne,
  JoinColumn,
  Index,
} from 'typeorm';
import { DocumentTemplateUserAssignment } from './document-template-user-assignment.entity';

/**
 * Append-only audit log of every lifecycle transition on a document
 * template assignment. Source of truth for "who did what when"
 * questions that the denormalized columns on
 * `document_template_user_assignments` can't answer once state is
 * overwritten — e.g. "this was rejected on day 1, fixed, and
 * approved on day 3" leaves only the final approval visible on the
 * assignment row, but every step is preserved here.
 *
 * Event types are intentionally free-form strings (not an enum) so
 * future flows can add 'reopened', 'reassigned', 'reminded', etc.
 * without a migration. The current set written by the service is:
 *   - 'created'    (assignment first created)
 *   - 'started'    (first field saved)
 *   - 'completed'  (final required field saved; system-driven)
 *   - 'submitted'  (employee marked done — only when requires_review)
 *   - 'approved'   (admin approved a submission)
 *   - 'rejected'   (admin rejected a submission, with reason)
 *   - 'reopened'   (admin reset to in_progress to allow re-fill)
 *
 * `actor_user_id` is null for system-driven events (the auto-completion
 * stamp on the last field save) and populated for human-driven events.
 * `payload` JSONB carries event-specific metadata (`from_status`,
 * `to_status`, `reason`, etc.).
 */
@Entity('document_assignment_events')
@Index(['assignment_id'])
@Index(['actor_user_id'])
export class DocumentAssignmentEvent {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  assignment_id: string;

  @Column({ type: 'varchar', length: 32 })
  event: string;

  @Column({ type: 'uuid', nullable: true })
  actor_user_id: string | null;

  @Column({ type: 'jsonb', nullable: true })
  payload: Record<string, unknown> | null;

  @CreateDateColumn({ type: 'timestamptz', default: () => 'now()' })
  created_at: Date;

  @ManyToOne(() => DocumentTemplateUserAssignment, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'assignment_id' })
  assignment: DocumentTemplateUserAssignment;
}
