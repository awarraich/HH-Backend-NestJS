import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  OneToOne,
  JoinColumn,
  OneToMany,
  Index,
} from 'typeorm';
import { User } from '../../../authentication/entities/user.entity';
import { OrganizationTypeAssignment } from './organization-type-assignment.entity';
import { OrganizationProfile } from './organization-profile.entity';
import { OrganizationRolePermission } from './organization-role-permission.entity';
import { OrganizationStaff } from '../staff-management/entities/organization-staff.entity';

@Entity('organizations')
@Index(['user_id'], { unique: true })
@Index(['organization_name'])
@Index(['tax_id'])
export class Organization {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid', unique: true })
  user_id: string;

  @Column({ type: 'varchar', length: 255, nullable: true })
  organization_name: string;

  @Column({ type: 'varchar', length: 20, nullable: true })
  tax_id: string;

  @Column({ type: 'varchar', length: 50, nullable: true })
  registration_number: string;

  @Column({ type: 'varchar', length: 200, nullable: true })
  website: string;

  @Column({ type: 'text', nullable: true })
  description: string;

  @CreateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  updated_at: Date;

  // Relations
  @OneToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user: User;

  @OneToMany(() => OrganizationTypeAssignment, (assignment) => assignment.organization)
  typeAssignments: OrganizationTypeAssignment[];

  @OneToOne(() => OrganizationProfile, (profile) => profile.organization)
  profile: OrganizationProfile;

  @OneToMany(() => OrganizationRolePermission, (permission) => permission.organization)
  rolePermissions: OrganizationRolePermission[];

  @OneToMany(() => OrganizationStaff, (staff) => staff.organization)
  staff: OrganizationStaff[];
}
