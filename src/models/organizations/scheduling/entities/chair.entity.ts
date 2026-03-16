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
import { Room } from './room.entity';

@Entity('chairs')
@Index(['room_id'])
@Index(['room_id', 'is_active'])
export class Chair {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  room_id: string;

  @Column({ type: 'varchar', length: 50 })
  chair_number: string;

  @Column({ type: 'boolean', default: true })
  is_active: boolean;

  @CreateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  updated_at: Date;

  @ManyToOne(() => Room, (room) => room.chairs, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'room_id' })
  room: Room;
}
