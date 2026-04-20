import {
  Entity,
  PrimaryColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';

@Entity('scheduling_task_types')
export class SchedulingTaskType {
  @PrimaryColumn({ type: 'varchar', length: 64 })
  code: string;

  @Column({ type: 'varchar', length: 128 })
  label: string;

  @Column({ type: 'jsonb', default: () => "'[]'" })
  organization_type_keys: string[];

  @Column({ type: 'jsonb', default: () => "'{}'" })
  default_statuses: {
    allowed: string[];
    initial: string;
    terminal?: string[];
    transitions?: Record<string, string[]>;
  };

  @Column({ type: 'jsonb', default: () => "'{}'" })
  resource_schema: Record<string, unknown>;

  @Column({ type: 'jsonb', default: () => "'{}'" })
  details_schema: Record<string, unknown>;

  @Column({ type: 'boolean', default: true })
  is_active: boolean;

  @CreateDateColumn({ type: 'timestamptz', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamptz', default: () => 'CURRENT_TIMESTAMP' })
  updated_at: Date;
}
