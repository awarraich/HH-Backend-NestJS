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
import { Station } from './station.entity';
import { Zone } from './zone.entity';
import { FleetVehicle } from './fleet-vehicle.entity';
import { LabWorkstation } from './lab-workstation.entity';
import { DepartmentShift } from './department-shift.entity';
import { DepartmentStaff } from './department-staff.entity';

@Entity('departments')
@Index(['organization_id'])
@Index(['organization_id', 'is_active'])
export class Department {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  organization_id: string;

  @Column({ type: 'varchar', length: 255 })
  name: string;

  @Column({ type: 'varchar', length: 50, nullable: true })
  code: string | null;

  @Column({ type: 'text', nullable: true })
  description: string | null;

  @Column({ type: 'varchar', length: 50, nullable: true })
  department_type: string | null;

  @Column({ type: 'varchar', length: 30, nullable: true })
  layout_type: string | null;

  @Column({ type: 'varchar', length: 255, nullable: true })
  department_head: string | null;

  @Column({ type: 'boolean', default: false })
  allow_multi_station_coverage: boolean;

  @Column({ type: 'boolean', default: true })
  is_active: boolean;

  @Column({ type: 'smallint', nullable: true })
  sort_order: number | null;

  @CreateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  updated_at: Date;

  @ManyToOne(() => Organization, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'organization_id' })
  organization: Organization;

  @OneToMany(() => Station, (station) => station.department)
  stations: Station[];

  @OneToMany(() => Zone, (zone) => zone.department)
  zones: Zone[];

  @OneToMany(() => FleetVehicle, (vehicle) => vehicle.department)
  fleetVehicles: FleetVehicle[];

  @OneToMany(() => LabWorkstation, (workstation) => workstation.department)
  labWorkstations: LabWorkstation[];

  @OneToMany(() => DepartmentShift, (ds) => ds.department)
  departmentShifts: DepartmentShift[];

  @OneToMany(() => DepartmentStaff, (staff) => staff.department)
  departmentStaff: DepartmentStaff[];

  stationCount?: number;
  zoneCount?: number;
  vehicleCount?: number;
  workstationCount?: number;
  staffCount?: number;
  shiftCount?: number;
}
