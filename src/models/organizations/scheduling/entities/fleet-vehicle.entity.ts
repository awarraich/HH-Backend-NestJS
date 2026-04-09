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
import { Department } from './department.entity';
import { VehicleShiftAssignment } from './vehicle-shift-assignment.entity';

@Entity('fleet_vehicles')
@Index(['department_id'])
export class FleetVehicle {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  department_id: string;

  @Column({ type: 'varchar', length: 255 })
  name: string;

  @Column({ type: 'varchar', length: 100, nullable: true })
  vehicle_id: string | null;

  @Column({ type: 'varchar', length: 50, nullable: true })
  vehicle_type: string | null;

  @Column({ type: 'smallint', default: 0 })
  capacity: number;

  @Column({ type: 'boolean', default: true })
  is_active: boolean;

  @Column({ type: 'smallint', nullable: true })
  sort_order: number | null;

  @CreateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  updated_at: Date;

  @ManyToOne(() => Department, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'department_id' })
  department: Department;

  @OneToMany(() => VehicleShiftAssignment, (vsa) => vsa.vehicle)
  shiftAssignments: VehicleShiftAssignment[];
}
