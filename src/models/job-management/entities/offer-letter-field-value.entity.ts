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

/**
 * Per-offer, per-field filled value.
 *
 * Unique on (assignment_id, field_id) — one row per field per offer letter.
 * `filled_by_user_id` + `filled_by_role_id` are audit metadata for who last
 * filled the field. Overwriting is intentional: the latest fill wins but we
 * always know which role/user wrote it.
 */
@Entity('offer_letter_field_values')
@Index(['assignment_id'])
@Unique(['assignment_id', 'field_id'])
export class OfferLetterFieldValue {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  assignment_id: string;

  @Column({ type: 'varchar', length: 255 })
  field_id: string;

  @Column({ type: 'uuid', nullable: true })
  filled_by_user_id: string | null;

  @Column({ type: 'uuid', nullable: true })
  filled_by_role_id: string | null;

  @Column({ type: 'text', nullable: true })
  value_text: string | null;

  @Column({ type: 'jsonb', nullable: true })
  value_json: Record<string, unknown> | null;

  /**
   * E-signature audit trail for signature/initials fields. Populated when
   * the filler agreed to an ESIGN consent before submitting. Shape:
   *   {
   *     consentVersion: string,
   *     consentText: string,
   *     ip: string | null,
   *     userAgent: string | null,
   *     documentHash: string | null,  // sha256 hex of the template bytes
   *     signedAt: string,             // ISO timestamp
   *   }
   * Null for non-signature fields or legacy rows written before consent
   * capture was enforced.
   */
  @Column({ type: 'jsonb', nullable: true })
  signature_audit: Record<string, unknown> | null;

  @CreateDateColumn({ type: 'timestamptz' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamptz' })
  updated_at: Date;

  @ManyToOne(() => OfferLetterAssignment, (a) => a.fieldValues, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'assignment_id' })
  assignment: OfferLetterAssignment;
}
