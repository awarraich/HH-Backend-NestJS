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

  // ── Safety & Compliance ───────────────────────────────────────────
  @Column({ type: 'smallint', default: 11 })
  min_rest_hours: number;

  @Column({ type: 'smallint', default: 5 })
  max_consecutive_days: number;

  @Column({ type: 'smallint', default: 12 })
  max_hours_per_day: number;

  @Column({ type: 'varchar', length: 20, default: 'sometimes' })
  double_shift_preference: string;

  @Column({ type: 'simple-array', default: 'overtime,emergency' })
  double_shift_conditions: string[];

  // ── Work Type & Location ──────────────────────────────────────────
  @Column({ type: 'varchar', length: 20, default: 'office' })
  work_type: string;

  @Column({ type: 'smallint', default: 25 })
  travel_radius: number;

  @Column({ type: 'boolean', default: true })
  has_own_vehicle: boolean;

  @Column({ type: 'boolean', default: false })
  use_company_vehicle: boolean;

  @Column({ type: 'simple-array', default: '' })
  preferred_areas: string[];

  @Column({ type: 'jsonb', default: '{}' })
  facilities: Record<string, boolean>;

  @Column({ type: 'jsonb', default: '{}' })
  weekly_notes: Record<string, string>;

  @CreateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  updated_at: Date;

  @OneToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user: User;
}
