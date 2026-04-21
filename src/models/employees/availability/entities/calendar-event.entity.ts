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
import { User } from '../../../../authentication/entities/user.entity';
import { Organization } from '../../../organizations/entities/organization.entity';

@Entity('calendar_events')
@Index(['user_id'])
@Index(['organization_id'])
@Index(['user_id', 'start_at'])
@Index(['status'])
export class CalendarEvent {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  user_id: string;

  @Column({ type: 'uuid', nullable: true })
  organization_id: string | null;

  @Column({ type: 'varchar', length: 255 })
  title: string;

  @Column({ type: 'text', nullable: true })
  description: string | null;

  @Column({ type: 'timestamptz' })
  start_at: Date;

  @Column({ type: 'timestamptz' })
  end_at: Date;

  @Column({ type: 'boolean', default: false })
  all_day: boolean;

  @Column({ type: 'varchar', length: 500, nullable: true })
  location: string | null;

  @Column({ type: 'varchar', length: 50, default: 'general' })
  event_type: string;

  @Column({ type: 'varchar', length: 20, nullable: true })
  color: string | null;

  @Column({ type: 'varchar', length: 255, nullable: true })
  recurrence_rule: string | null;

  @Column({ type: 'date', nullable: true })
  recurrence_end_date: Date | null;

  @Column({ type: 'varchar', length: 100, default: 'America/Los_Angeles' })
  timezone: string;

  @Column({ type: 'varchar', length: 20, default: 'active' })
  status: string;

  @CreateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  updated_at: Date;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user: User;

  @ManyToOne(() => Organization, { onDelete: 'CASCADE', nullable: true })
  @JoinColumn({ name: 'organization_id' })
  organization: Organization | null;
}
