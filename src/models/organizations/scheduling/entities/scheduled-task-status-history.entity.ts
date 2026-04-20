import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
  CreateDateColumn,
  Index,
} from 'typeorm';
import { ScheduledTask } from './scheduled-task.entity';

@Entity('scheduled_task_status_history')
@Index(['scheduled_task_id'])
export class ScheduledTaskStatusHistory {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  scheduled_task_id: string;

  @Column({ type: 'varchar', length: 32, nullable: true })
  from_status: string | null;

  @Column({ type: 'varchar', length: 32 })
  to_status: string;

  @Column({ type: 'uuid', nullable: true })
  changed_by: string | null;

  @CreateDateColumn({ type: 'timestamptz', default: () => 'CURRENT_TIMESTAMP' })
  changed_at: Date;

  @Column({ type: 'text', nullable: true })
  reason: string | null;

  @ManyToOne(() => ScheduledTask, (t) => t.statusHistory, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'scheduled_task_id' })
  scheduledTask: ScheduledTask;
}
