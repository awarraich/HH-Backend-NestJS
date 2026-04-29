import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
  Unique,
} from 'typeorm';

@Entity('document_field_values')
@Index(['template_id'])
@Index(['user_id'])
@Index(['template_id', 'user_id'])
@Unique(['template_id', 'field_id', 'user_id'])
export class DocumentFieldValue {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  template_id: string;

  @Column({ type: 'varchar', length: 255 })
  field_id: string;

  @Column({ type: 'uuid' })
  user_id: string;

  @Column({ type: 'jsonb', default: null, nullable: true })
  value: any;

  /**
   * E-signature audit trail. Populated when the field being saved is a
   * signature/initials field; null for plain text fields and for legacy
   * rows written before this column existed. Same JSON shape used by
   * `OfferLetterFieldValue.signature_audit` so the frontend
   * SignedDocumentInfo block can render uniformly across both flows.
   *
   * Shape: see migration 20260429110000.
   */
  @Column({ type: 'jsonb', default: null, nullable: true })
  signature_audit: Record<string, unknown> | null;

  @CreateDateColumn({ type: 'timestamptz', default: () => 'now()' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamptz', default: () => 'now()' })
  updated_at: Date;
}
