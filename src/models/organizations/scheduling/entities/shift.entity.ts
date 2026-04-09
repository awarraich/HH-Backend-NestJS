import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  OneToMany,
  JoinColumn,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
} from 'typeorm';
import { Organization } from '../../entities/organization.entity';
import { EmployeeShift } from './employee-shift.entity';
import { ShiftRole } from './shift-role.entity';
import { DepartmentShift } from './department-shift.entity';

@Entity('shifts')
@Index(['organization_id'])
@Index(['organization_id', 'start_at'])
@Index(['organization_id', 'status'])
export class Shift {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  organization_id: string;

  @Column({ type: 'timestamp' })
  start_at: Date;

  @Column({ type: 'timestamp' })
  end_at: Date;

  @Column({ type: 'varchar', length: 50, nullable: true })
  shift_type: string | null;

  @Column({ type: 'varchar', length: 255, nullable: true })
  name: string | null;

  @Column({ type: 'varchar', length: 20, default: 'ACTIVE' })
  status: string;

  @Column({ type: 'varchar', length: 20, default: 'ONE_TIME' })
  recurrence_type: string;

  @Column({ type: 'simple-array', nullable: true })
  recurrence_days: string | null;

  @Column({ type: 'date', nullable: true })
  recurrence_start_date: Date | null;

  @Column({ type: 'date', nullable: true })
  recurrence_end_date: Date | null;

  @CreateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  updated_at: Date;

  @ManyToOne(() => Organization, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'organization_id' })
  organization: Organization;

  @OneToMany(() => EmployeeShift, (es) => es.shift)
  employeeShifts: EmployeeShift[];

  @OneToMany(() => ShiftRole, (sr) => sr.shift)
  shiftRoles: ShiftRole[];

  @OneToMany(() => DepartmentShift, (ds) => ds.shift)
  departmentShifts: DepartmentShift[];
}
