import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
  Unique,
} from 'typeorm';
import { User } from '../../../../authentication/entities/user.entity';
import { Organization } from '../../entities/organization.entity';
import { StaffRole } from './staff-role.entity';

@Entity('organization_staff')
@Unique(['organization_id', 'user_id', 'staff_role_id'])
@Index(['organization_id'])
@Index(['user_id'])
@Index(['staff_role_id'])
@Index(['organization_id', 'status'])
export class OrganizationStaff {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  organization_id: string;

  @Column({ type: 'uuid' })
  user_id: string;

  @Column({ type: 'uuid' })
  staff_role_id: string;

  @Column({ type: 'varchar', length: 20, default: 'ACTIVE' })
  status: string;

  @Column({ type: 'date', nullable: true })
  start_date: Date | null;

  @Column({ type: 'date', nullable: true })
  end_date: Date | null;

  @Column({ type: 'varchar', length: 100, nullable: true })
  department: string | null;

  @Column({ type: 'varchar', length: 100, nullable: true })
  position_title: string | null;

  @CreateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  updated_at: Date;

  @Column({ type: 'uuid', nullable: true })
  created_by: string | null;

  @Column({ type: 'uuid', nullable: true })
  updated_by: string | null;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user: User;

  @ManyToOne(() => Organization, (org) => org.staff, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'organization_id' })
  organization: Organization;

  @ManyToOne(() => StaffRole, (role) => role.organizationStaff, { onDelete: 'RESTRICT' })
  @JoinColumn({ name: 'staff_role_id' })
  staffRole: StaffRole;
}
