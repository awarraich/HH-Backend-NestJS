import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  Index,
  OneToMany,
} from 'typeorm';
import { OrganizationStaff } from './organization-staff.entity';
import { OrganizationStaffRolePermission } from './organization-staff-role-permission.entity';

@Entity('staff_roles')
@Index(['name'], { unique: true })
export class StaffRole {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'varchar', length: 50, unique: true })
  name: string;

  @Column({ type: 'text', nullable: true })
  description: string | null;

  @CreateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;

  @OneToMany(() => OrganizationStaff, (orgStaff) => orgStaff.staffRole)
  organizationStaff: OrganizationStaff[];

  @OneToMany(() => OrganizationStaffRolePermission, (perm) => perm.staffRole)
  permissions: OrganizationStaffRolePermission[];
}
