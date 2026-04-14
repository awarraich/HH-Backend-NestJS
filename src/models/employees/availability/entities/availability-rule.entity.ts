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

@Entity('availability_rules')
@Index(['user_id'])
@Index(['organization_id'])
@Index(['user_id', 'day_of_week'])
export class AvailabilityRule {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  user_id: string;

  @Column({ type: 'uuid', nullable: true })
  organization_id: string | null;

  @Column({ type: 'date', nullable: true })
  date: string | null;

  @Column({ type: 'smallint', nullable: true })
  day_of_week: number | null;

  @Column({ type: 'time' })
  start_time: string;

  @Column({ type: 'time' })
  end_time: string;

  @Column({ type: 'boolean', default: true })
  is_available: boolean;

  @Column({ type: 'varchar', length: 50, nullable: true })
  shift_type: string | null;

  @Column({ type: 'date', nullable: true })
  effective_from: Date | null;

  @Column({ type: 'date', nullable: true })
  effective_until: Date | null;

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
