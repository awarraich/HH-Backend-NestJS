import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  OneToMany,
  JoinColumn,
  CreateDateColumn,
  UpdateDateColumn,
  DeleteDateColumn,
  Index,
} from 'typeorm';
import { Organization } from '../../entities/organization.entity';
import { SchedulingTaskType } from './scheduling-task-type.entity';
import { Department } from './department.entity';
import { Station } from './station.entity';
import { Room } from './room.entity';
import { Bed } from './bed.entity';
import { Chair } from './chair.entity';
import { Zone } from './zone.entity';
import { FleetVehicle } from './fleet-vehicle.entity';
import { LabWorkstation } from './lab-workstation.entity';
import { Shift } from './shift.entity';
import { ScheduledTaskAssignment } from './scheduled-task-assignment.entity';
import { ScheduledTaskStatusHistory } from './scheduled-task-status-history.entity';

@Entity('scheduled_tasks')
@Index(['organization_id', 'task_type_code', 'scheduled_start_at'])
@Index(['organization_id', 'task_type_code', 'status'])
@Index(['scheduled_start_at'])
export class ScheduledTask {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  organization_id: string;

  @Column({ type: 'varchar', length: 64 })
  task_type_code: string;

  @Column({ type: 'varchar', length: 32, default: 'scheduled' })
  status: string;

  @Column({ type: 'smallint', default: 2 })
  priority: number;

  @Column({ type: 'timestamptz' })
  scheduled_start_at: Date;

  @Column({ type: 'timestamptz' })
  scheduled_end_at: Date;

  @Column({ type: 'timestamptz', nullable: true })
  actual_start_at: Date | null;

  @Column({ type: 'timestamptz', nullable: true })
  actual_end_at: Date | null;

  @Column({ type: 'uuid', nullable: true })
  department_id: string | null;

  @Column({ type: 'uuid', nullable: true })
  station_id: string | null;

  @Column({ type: 'uuid', nullable: true })
  room_id: string | null;

  @Column({ type: 'uuid', nullable: true })
  bed_id: string | null;

  @Column({ type: 'uuid', nullable: true })
  chair_id: string | null;

  @Column({ type: 'uuid', nullable: true })
  zone_id: string | null;

  @Column({ type: 'uuid', nullable: true })
  fleet_vehicle_id: string | null;

  @Column({ type: 'uuid', nullable: true })
  lab_workstation_id: string | null;

  @Column({ type: 'uuid', nullable: true })
  shift_id: string | null;

  @Column({ type: 'varchar', length: 255, nullable: true })
  subject_name: string | null;

  @Column({ type: 'varchar', length: 64, nullable: true })
  subject_phone: string | null;

  @Column({ type: 'text', nullable: true })
  subject_address: string | null;

  @Column({ type: 'text', nullable: true })
  notes: string | null;

  @Column({ type: 'jsonb', default: () => "'{}'" })
  details: Record<string, unknown>;

  @Column({ type: 'uuid', nullable: true })
  created_by: string | null;

  @Column({ type: 'uuid', nullable: true })
  updated_by: string | null;

  @CreateDateColumn({ type: 'timestamptz', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamptz', default: () => 'CURRENT_TIMESTAMP' })
  updated_at: Date;

  @DeleteDateColumn({ type: 'timestamptz', nullable: true })
  deleted_at: Date | null;

  @ManyToOne(() => Organization, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'organization_id' })
  organization: Organization;

  @ManyToOne(() => SchedulingTaskType, { onDelete: 'RESTRICT' })
  @JoinColumn({ name: 'task_type_code', referencedColumnName: 'code' })
  taskType: SchedulingTaskType;

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

  @ManyToOne(() => Chair, { onDelete: 'SET NULL' })
  @JoinColumn({ name: 'chair_id' })
  chair: Chair | null;

  @ManyToOne(() => Zone, { onDelete: 'SET NULL' })
  @JoinColumn({ name: 'zone_id' })
  zone: Zone | null;

  @ManyToOne(() => FleetVehicle, { onDelete: 'SET NULL' })
  @JoinColumn({ name: 'fleet_vehicle_id' })
  fleetVehicle: FleetVehicle | null;

  @ManyToOne(() => LabWorkstation, { onDelete: 'SET NULL' })
  @JoinColumn({ name: 'lab_workstation_id' })
  labWorkstation: LabWorkstation | null;

  @ManyToOne(() => Shift, { onDelete: 'SET NULL' })
  @JoinColumn({ name: 'shift_id' })
  shift: Shift | null;

  @OneToMany(() => ScheduledTaskAssignment, (a) => a.scheduledTask)
  assignments: ScheduledTaskAssignment[];

  @OneToMany(() => ScheduledTaskStatusHistory, (h) => h.scheduledTask)
  statusHistory: ScheduledTaskStatusHistory[];
}
