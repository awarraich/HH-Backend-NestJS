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
import { ScheduledTask } from './scheduled-task.entity';
import { Employee } from '../../../employees/entities/employee.entity';
import { EmployeeShift } from './employee-shift.entity';

@Entity('scheduled_task_assignments')
@Unique(['scheduled_task_id', 'employee_id', 'assignment_role'])
@Index(['scheduled_task_id'])
@Index(['employee_id'])
export class ScheduledTaskAssignment {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  scheduled_task_id: string;

  @Column({ type: 'uuid' })
  employee_id: string;

  @Column({ type: 'uuid', nullable: true })
  employee_shift_id: string | null;

  @Column({ type: 'varchar', length: 64 })
  assignment_role: string;

  @Column({ type: 'boolean', default: true })
  is_primary: boolean;

  @CreateDateColumn({ type: 'timestamptz', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamptz', default: () => 'CURRENT_TIMESTAMP' })
  updated_at: Date;

  @ManyToOne(() => ScheduledTask, (t) => t.assignments, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'scheduled_task_id' })
  scheduledTask: ScheduledTask;

  @ManyToOne(() => Employee, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'employee_id' })
  employee: Employee;

  @ManyToOne(() => EmployeeShift, { onDelete: 'SET NULL' })
  @JoinColumn({ name: 'employee_shift_id' })
  employeeShift: EmployeeShift | null;
}
