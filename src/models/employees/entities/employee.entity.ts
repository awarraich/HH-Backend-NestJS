import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  OneToOne,
  JoinColumn,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
  Unique,
} from 'typeorm';
import { User } from '../../../authentication/entities/user.entity';
import { Organization } from '../../organizations/entities/organization.entity';
import { EmployeeProfile } from './employee-profile.entity';
import { ProviderRole } from './provider-role.entity';

@Entity('employees')
@Index(['user_id'])
@Index(['organization_id'])
@Unique(['user_id', 'organization_id'])
@Index(['status'])
@Index(['organization_id', 'status'])
@Index(['provider_role_id'])
@Index(['employment_type'])
export class Employee {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  user_id: string;

  @Column({ type: 'uuid', nullable: true })
  organization_id: string | null;

  @Column({ type: 'varchar', length: 20, default: 'active' })
  status: string;

  @Column({ type: 'varchar', length: 20, nullable: true })
  employment_type: string | null;

  @Column({ type: 'date', nullable: true })
  start_date: Date | null;

  @Column({ type: 'date', nullable: true })
  end_date: Date | null;

  @Column({ type: 'varchar', length: 100, nullable: true })
  department: string | null;

  @Column({ type: 'varchar', length: 100, nullable: true })
  position_title: string | null;

  @Column({ type: 'text', nullable: true })
  notes: string | null;

  @Column({ type: 'uuid', nullable: true })
  provider_role_id: string | null;

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

  @ManyToOne(() => ProviderRole, { onDelete: 'SET NULL', nullable: true })
  @JoinColumn({ name: 'provider_role_id' })
  providerRole: ProviderRole | null;

  @OneToOne(() => EmployeeProfile, (profile) => profile.employee)
  profile: EmployeeProfile;
}
