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
import { CompetencyTemplate } from './competency-template.entity';

@Entity('competency_assignments')
@Index(['organization_id'])
@Index(['organization_id', 'status'])
@Index(['supervisor_id'])
@Index(['template_id'])
export class CompetencyAssignment {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  organization_id: string;

  @Column({ type: 'uuid' })
  template_id: string;

  @Column({ type: 'jsonb' })
  template_snapshot: Record<string, any>;

  @Column({ type: 'varchar', length: 255 })
  name: string;

  @Column({ type: 'uuid' })
  supervisor_id: string;

  @Column({ type: 'varchar', length: 20, default: 'sent' })
  status: string;

  @Column({ type: 'jsonb', default: {} })
  field_values: Record<string, string>;

  @Column({ type: 'text', nullable: true })
  employee_signature: string | null;

  @Column({ type: 'timestamptz', nullable: true })
  employee_signed_at: Date | null;

  @Column({ type: 'timestamptz', nullable: true })
  completed_at: Date | null;

  @Column({ type: 'uuid', nullable: true })
  created_by: string | null;

  @CreateDateColumn({ type: 'timestamptz', default: () => 'now()' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamptz', default: () => 'now()' })
  updated_at: Date;

  @ManyToOne(() => CompetencyTemplate, { onDelete: 'RESTRICT' })
  @JoinColumn({ name: 'template_id' })
  template: CompetencyTemplate;
}
