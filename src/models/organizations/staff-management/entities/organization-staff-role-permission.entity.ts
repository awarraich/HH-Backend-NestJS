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
import { Organization } from '../../entities/organization.entity';
import { StaffRole } from './staff-role.entity';

@Entity('organization_staff_role_permissions')
@Unique(['organization_id', 'staff_role_id', 'feature'])
@Index(['organization_id'])
@Index(['staff_role_id'])
@Index(['feature'])
export class OrganizationStaffRolePermission {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  organization_id: string;

  @Column({ type: 'uuid' })
  staff_role_id: string;

  @Column({ type: 'varchar', length: 100 })
  feature: string;

  @Column({ type: 'boolean', default: false })
  has_access: boolean;

  @CreateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  updated_at: Date;

  @ManyToOne(() => Organization, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'organization_id' })
  organization: Organization;

  @ManyToOne(() => StaffRole, (role) => role.permissions, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'staff_role_id' })
  staffRole: StaffRole;
}
