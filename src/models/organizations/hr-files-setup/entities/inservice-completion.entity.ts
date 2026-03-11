import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
  Unique,
} from 'typeorm';
import { Employee } from '../../../employees/entities/employee.entity';
import { InserviceTraining } from './inservice-training.entity';

@Entity('inservice_completions')
@Unique(['employee_id', 'inservice_training_id'])
@Index(['employee_id'])
@Index(['inservice_training_id'])
export class InserviceCompletion {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  employee_id: string;

  @Column({ type: 'uuid' })
  inservice_training_id: string;

  @Column({ type: 'integer', default: 0 })
  progress_percent: number;

  @Column({ type: 'timestamp with time zone', nullable: true })
  completed_at: Date | null;

  @Column({ type: 'timestamp with time zone', nullable: true })
  expiration_at: Date | null;

  @Column({ type: 'integer', nullable: true })
  last_quiz_score_percent: number | null;

  @Column({ type: 'integer', default: 0 })
  quiz_attempts_count: number;

  @CreateDateColumn({ type: 'timestamp with time zone', default: () => 'NOW()' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamp with time zone', default: () => 'NOW()' })
  updated_at: Date;

  @ManyToOne(() => Employee, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'employee_id' })
  employee: Employee;

  @ManyToOne(() => InserviceTraining, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'inservice_training_id' })
  inserviceTraining: InserviceTraining;
}
