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
import { Station } from './station.entity';
import { Bed } from './bed.entity';
import { Chair } from './chair.entity';

@Entity('rooms')
@Index(['station_id'])
@Index(['station_id', 'is_active'])
export class Room {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  station_id: string;

  @Column({ type: 'varchar', length: 100 })
  name: string;

  @Column({ type: 'varchar', length: 255, nullable: true })
  location_or_wing: string | null;

  @Column({ type: 'varchar', length: 50, nullable: true })
  floor: string | null;

  @Column({ type: 'varchar', length: 20, nullable: true })
  configuration_type: string | null;

  @Column({ type: 'smallint', nullable: true })
  beds_per_room: number | null;

  @Column({ type: 'smallint', nullable: true })
  chairs_per_room: number | null;

  @Column({ type: 'boolean', default: true })
  is_active: boolean;

  @Column({ type: 'smallint', nullable: true })
  sort_order: number | null;

  @CreateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  updated_at: Date;

  @ManyToOne(() => Station, (station) => station.rooms, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'station_id' })
  station: Station;

  @OneToMany(() => Bed, (bed) => bed.room)
  beds: Bed[];

  @OneToMany(() => Chair, (chair) => chair.room)
  chairs: Chair[];
}
