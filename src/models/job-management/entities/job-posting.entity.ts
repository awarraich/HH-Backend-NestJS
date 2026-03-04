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

  @CreateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  updated_at: Date;

  @ManyToOne(() => Organization, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'organization_id' })
  organization: Organization;
}
