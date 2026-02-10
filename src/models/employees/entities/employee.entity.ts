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

@Entity('employees')
@Index(['user_id'])
@Index(['organization_id'])
@Unique(['user_id', 'organization_id'])
@Index(['status'])
@Index(['role'])
@Index(['organization_id', 'status'])
export class Employee {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  user_id: string;

  @Column({ type: 'uuid' })
  organization_id: string;

  @Column({ type: 'varchar', length: 20 })
  role: string; // ADMIN | PROVIDER | STAFF | HR | ASSISTANT_HR | BILLER | SCHEDULER | FRONT_DESK | OFFICE_STAFF

  @Column({ type: 'varchar', length: 20, default: 'active' })
  status: string; // ACTIVE | INVITED | INACTIVE | TERMINATED

  @Column({ type: 'date', nullable: true })
  start_date: Date | null;

  @Column({ type: 'date', nullable: true })
  end_date: Date | null;

  @Column({ type: 'varchar', length: 100, nullable: true })
  department: string;

  @Column({ type: 'varchar', length: 100, nullable: true })
  position_title: string;

  @CreateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  updated_at: Date;

  // Relations
  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user: User;

  @ManyToOne(() => Organization, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'organization_id' })
  organization: Organization;

  @OneToOne(() => EmployeeProfile, (profile) => profile.employee)
  profile: EmployeeProfile;
}
