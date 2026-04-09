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
import { Department } from './department.entity';

@Entity('department_staff')
@Index(['department_id'])
export class DepartmentStaff {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  department_id: string;

  @Column({ type: 'varchar', length: 50 })
  staff_type: string;

  @Column({ type: 'varchar', length: 100 })
  staff_name: string;

  @Column({ type: 'smallint', default: 1 })
  quantity: number;

  @Column({ type: 'varchar', length: 50, nullable: true })
  assignment_level: string | null;

  @Column({ type: 'varchar', length: 20, nullable: true })
  assignment_type: string | null;

  @Column({ type: 'jsonb', nullable: true })
  shift_ids: string[] | null;

  @Column({ type: 'jsonb', nullable: true })
  staff_by_shift: Record<string, number> | null;

  @Column({ type: 'jsonb', nullable: true })
  staff_min_max_by_shift: Record<string, { min?: number; max?: number }> | null;

  @Column({ type: 'smallint', nullable: true })
  sort_order: number | null;

  @CreateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  updated_at: Date;

  @ManyToOne(() => Department, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'department_id' })
  department: Department;
}
