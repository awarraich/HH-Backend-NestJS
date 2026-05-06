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

/**
 * Per-instance, per-field filled value for the v2 role-scoped competency
 * fill flow. Unique on `(assignment_id, field_id)` — one row per field per
 * instance — so two different employees with the same template+supervisor
 * never collide on the legacy `document_field_values(template_id, field_id,
 * user_id)` keying.
 *
 * `signature_audit` carries the SignedDocumentInfo block (consent version,
 * IP/UA, signedAt, signer name/title, geolocation) for signature/initials
 * fields; null otherwise. Same shape as `offer_letter_field_values`.
 */
@Entity('competency_assignment_field_values')
@Index(['assignment_id'])
@Unique(['assignment_id', 'field_id'])
export class CompetencyAssignmentFieldValue {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  assignment_id: string;

  @Column({ type: 'varchar', length: 255 })
  field_id: string;

  @Column({ type: 'text', nullable: true })
  value_text: string | null;

  @Column({ type: 'jsonb', nullable: true })
  value_json: Record<string, unknown> | null;

  @Column({ type: 'uuid', nullable: true })
  filled_by_user_id: string | null;

  @Column({ type: 'uuid', nullable: true })
  filled_by_role_id: string | null;

  @Column({ type: 'jsonb', nullable: true })
  signature_audit: Record<string, unknown> | null;

  @CreateDateColumn({ type: 'timestamptz' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamptz' })
  updated_at: Date;

  @ManyToOne(() => CompetencyAssignment, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'assignment_id' })
  assignment: CompetencyAssignment;
}
