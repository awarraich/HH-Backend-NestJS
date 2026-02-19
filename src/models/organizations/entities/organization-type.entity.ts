import { Entity, PrimaryColumn, Column, CreateDateColumn, OneToMany, Index } from 'typeorm';
import { OrganizationTypeAssignment } from './organization-type-assignment.entity';

@Entity('organization_types')
@Index(['name'], { unique: true })
export class OrganizationType {
  @PrimaryColumn({ type: 'smallint' })
  id: number;

  @Column({ type: 'varchar', length: 50, unique: true })
  name: string; // HOME HEALTH | HOSPICE | NURSING HOME | BOARD AND CARE | PHARMACIST | LAB

  @CreateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;

  // Relations
  @OneToMany(() => OrganizationTypeAssignment, (assignment) => assignment.organizationType)
  assignments: OrganizationTypeAssignment[];
}
