import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
  CreateDateColumn,
  Unique,
} from 'typeorm';
import { Department } from './department.entity';
import { Shift } from './shift.entity';

@Entity('department_shifts')
@Unique('uq_department_shifts', ['department_id', 'shift_id'])
export class DepartmentShift {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  department_id: string;

  @Column({ type: 'uuid' })
  shift_id: string;

  @CreateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;

  @ManyToOne(() => Department, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'department_id' })
  department: Department;

  @ManyToOne(() => Shift, { onDelete: 'CASCADE', eager: true })
  @JoinColumn({ name: 'shift_id' })
  shift: Shift;
}
