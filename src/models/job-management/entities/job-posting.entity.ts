import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  ManyToOne,
  JoinColumn,
  Index,
} from 'typeorm';
import { Organization } from '../../organizations/entities/organization.entity';

@Entity('job_postings')
@Index(['organization_id'])
@Index(['status'])
@Index(['organization_id', 'status'])
export class JobPosting {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  organization_id: string;

  @Column({ type: 'varchar', length: 500 })
  title: string;

  @Column({ type: 'text', nullable: true })
  description: string | null;

  @Column({ type: 'varchar', length: 255, nullable: true })
  location: string | null;

  @Column({ type: 'varchar', length: 50, nullable: true, default: 'in_person' })
  location_type: string | null;

  @Column({ type: 'varchar', length: 255, nullable: true })
  salary_range: string | null;

  @Column({ type: 'timestamp', nullable: true })
  application_deadline: Date | null;

  @Column({ type: 'varchar', length: 30, default: 'active' })
  status: string; // active | closed | filled

  /** Extra fields (job_types, benefits, requirements, etc.) stored as JSON */
  @Column({ type: 'jsonb', nullable: true })
  details: Record<string, unknown> | null;

  /**
   * Per-job snapshot of the application form field definitions.
   *
   * This is the source of truth for what applicants see when applying to this
   * specific posting. It is seeded from the organization's Application Form
   * Setup at create time and then evolves independently of it — so editing
   * the org setup later never mutates past postings. Each item is a full
   * definition: { id, label, type, required, placeholder?, options? }.
   *
   * Nullable for backward compatibility with postings created before this
   * column existed; those continue to resolve via the org setup + the
   * `details.required_fields` / `details.optional_fields` ID arrays.
   */
  @Column({ type: 'jsonb', nullable: true })
  application_fields_snapshot: Array<{
    id: string;
    label: string;
    type: string;
    required: boolean;
    placeholder?: string;
    options?: string[];
  }> | null;

  @CreateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  updated_at: Date;

  @ManyToOne(() => Organization, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'organization_id' })
  organization: Organization;
}
