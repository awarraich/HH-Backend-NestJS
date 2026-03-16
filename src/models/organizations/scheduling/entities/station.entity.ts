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
import { Room } from './room.entity';

@Entity('stations')
@Index(['department_id'])
@Index(['department_id', 'is_active'])
export class Station {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  department_id: string;

  @Column({ type: 'varchar', length: 255 })
  name: string;

  @Column({ type: 'varchar', length: 255, nullable: true })
  location: string | null;

  @Column({ type: 'varchar', length: 50, nullable: true })
  code: string | null;

  @Column({ type: 'smallint', default: 0 })
  required_charge_nurses: number;

  @Column({ type: 'smallint', default: 0 })
  required_cnas: number;

  @Column({ type: 'smallint', default: 0 })
  required_sitters: number;

  @Column({ type: 'smallint', default: 0 })
  required_treatment_nurses: number;

  @Column({ type: 'smallint', default: 0 })
  required_nps: number;

  @Column({ type: 'smallint', default: 0 })
  required_mds: number;

  @Column({ type: 'boolean', default: false })
  multi_station_am: boolean;

  @Column({ type: 'boolean', default: false })
  multi_station_pm: boolean;

  @Column({ type: 'boolean', default: false })
  multi_station_noc: boolean;

  @Column({ type: 'varchar', length: 20, nullable: true })
  configuration_type: string | null;

  @Column({ type: 'smallint', nullable: true })
  default_beds_per_room: number | null;

  @Column({ type: 'smallint', nullable: true })
  default_chairs_per_room: number | null;

  @Column({ type: 'jsonb', nullable: true })
  custom_shift_times: Record<string, { start: string; end: string }> | null;

  @Column({ type: 'boolean', default: true })
  is_active: boolean;

  @Column({ type: 'smallint', nullable: true })
  sort_order: number | null;

  @CreateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  updated_at: Date;

  @ManyToOne(() => Department, (dept) => dept.stations, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'department_id' })
  department: Department;

  @OneToMany(() => Room, (room) => room.station)
  rooms: Room[];
}
