import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  OneToOne,
  JoinColumn,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
} from 'typeorm';
import { User } from '../../../../authentication/entities/user.entity';

@Entity('work_preferences')
@Index(['user_id'])
export class WorkPreference {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid', unique: true })
  user_id: string;

  @Column({ type: 'smallint', default: 40 })
  max_hours_per_week: number;

  @Column({ type: 'varchar', length: 50, default: 'morning' })
  preferred_shift_type: string;

  @Column({ type: 'boolean', default: false })
  available_for_overtime: boolean;

  @Column({ type: 'boolean', default: false })
  available_for_on_call: boolean;

  @CreateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  updated_at: Date;

  @OneToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user: User;
}
