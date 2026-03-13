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
import { Shift } from './shift.entity';
import { Employee } from '../../../employees/entities/employee.entity';
import { Department } from './department.entity';
import { Station } from './station.entity';
import { Room } from './room.entity';
import { Bed } from './bed.entity';

@Entity('employee_shifts')
@Unique(['shift_id', 'employee_id'])
@Index(['shift_id'])
@Index(['employee_id'])
@Index(['employee_id', 'status'])
export class EmployeeShift {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  shift_id: string;

  @Column({ type: 'uuid' })
  employee_id: string;

  @Column({ type: 'uuid', nullable: true })
  department_id: string | null;

  @Column({ type: 'uuid', nullable: true })
  station_id: string | null;

  @Column({ type: 'uuid', nullable: true })
  room_id: string | null;

  @Column({ type: 'uuid', nullable: true })
  bed_id: string | null;

  @Column({ type: 'varchar', length: 20, default: 'SCHEDULED' })
  status: string;

  @Column({ type: 'text', nullable: true })
  notes: string | null;

  @Column({ type: 'timestamp', nullable: true })
  actual_start_at: Date | null;

  @Column({ type: 'timestamp', nullable: true })
  actual_end_at: Date | null;

  @CreateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  updated_at: Date;

  @ManyToOne(() => Shift, (shift) => shift.employeeShifts, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'shift_id' })
  shift: Shift;

  @ManyToOne(() => Employee, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'employee_id' })
  employee: Employee;

  @ManyToOne(() => Department, { onDelete: 'SET NULL' })
  @JoinColumn({ name: 'department_id' })
  department: Department | null;

  @ManyToOne(() => Station, { onDelete: 'SET NULL' })
  @JoinColumn({ name: 'station_id' })
  station: Station | null;

  @ManyToOne(() => Room, { onDelete: 'SET NULL' })
  @JoinColumn({ name: 'room_id' })
  room: Room | null;

  @ManyToOne(() => Bed, { onDelete: 'SET NULL' })
  @JoinColumn({ name: 'bed_id' })
  bed: Bed | null;
}
