import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
} from 'typeorm';
import { Organization } from '../../entities/organization.entity';

@Entity('inservice_trainings')
@Index(['organization_id'])
@Index(['organization_id', 'is_active'])
export class InserviceTraining {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  organization_id: string;

  @Column({ type: 'varchar', length: 20 })
  code: string;

  @Column({ type: 'varchar', length: 255 })
  title: string;

  @Column({ type: 'text', nullable: true })
  description: string | null;

  @Column({ type: 'varchar', length: 50 })
  completion_frequency: string;

  @Column({ type: 'integer', nullable: true })
  expiry_months: number | null;

  @Column({ type: 'jsonb', default: [] })
  pdf_files: Array<{
    file_name: string;
    file_path: string;
    file_size_bytes: number;
    title?: string;
  }>;

  @Column({ type: 'jsonb', default: [] })
  video_urls: string[];

  @Column({ type: 'jsonb', default: [] })
  video_titles: string[];

  @Column({ type: 'integer', default: 0 })
  sort_order: number;

  @Column({ type: 'boolean', default: true })
  is_active: boolean;

  @Column({ type: 'boolean', default: false })
  has_quiz: boolean;

  @Column({ type: 'integer', nullable: true })
  passing_score_percent: number | null;

  @CreateDateColumn({ type: 'timestamp with time zone', default: () => 'NOW()' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamp with time zone', default: () => 'NOW()' })
  updated_at: Date;

  @ManyToOne(() => Organization, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'organization_id' })
  organization: Organization;
}
