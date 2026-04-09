import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
  CreateDateColumn,
  Unique,
} from 'typeorm';
import { FleetVehicle } from './fleet-vehicle.entity';
import { Shift } from './shift.entity';

@Entity('vehicle_shift_assignments')
@Unique('uq_vehicle_shift_assignments', ['vehicle_id', 'shift_id'])
export class VehicleShiftAssignment {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  vehicle_id: string;

  @Column({ type: 'uuid' })
  shift_id: string;

  @CreateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;

  @ManyToOne(() => FleetVehicle, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'vehicle_id' })
  vehicle: FleetVehicle;

  @ManyToOne(() => Shift, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'shift_id' })
  shift: Shift;
}
