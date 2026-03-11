import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  Index,
  OneToMany,
} from 'typeorm';
import { OrganizationStaffRolePermission } from '../staff-management/entities/organization-staff-role-permission.entity';

@Entity('organization_features')
@Index(['code'], { unique: true })
export class OrganizationFeature {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'varchar', length: 100, unique: true })
  code: string;

  @Column({ type: 'varchar', length: 255, nullable: true })
  name: string | null;

  @Column({ type: 'text', nullable: true })
  description: string | null;

  @CreateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;

  @OneToMany(() => OrganizationStaffRolePermission, (perm) => perm.organizationFeature)
  staffRolePermissions: OrganizationStaffRolePermission[];
}
