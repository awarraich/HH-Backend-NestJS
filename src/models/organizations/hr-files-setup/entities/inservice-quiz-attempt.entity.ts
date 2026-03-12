import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
  CreateDateColumn,
  Index,
} from 'typeorm';
import { Employee } from '../../../employees/entities/employee.entity';
import { InserviceTraining } from './inservice-training.entity';

@Entity('inservice_quiz_attempts')
@Index(['employee_id'])
@Index(['inservice_training_id'])
export class InserviceQuizAttempt {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  employee_id: string;

  @Column({ type: 'uuid' })
  inservice_training_id: string;

  @Column({ type: 'integer' })
  score_percent: number;

  @Column({ type: 'boolean' })
  passed: boolean;

  @CreateDateColumn({ type: 'timestamp with time zone', default: () => 'NOW()' })
  created_at: Date;

  @ManyToOne(() => Employee, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'employee_id' })
  employee: Employee;

  @ManyToOne(() => InserviceTraining, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'inservice_training_id' })
  inserviceTraining: InserviceTraining;
}
