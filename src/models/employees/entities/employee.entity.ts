import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  OneToOne,
  OneToMany,
  JoinColumn,
  CreateDateColumn,
  UpdateDateColumn,
  DeleteDateColumn,
  Index,
} from 'typeorm';
import { User } from '../../../authentication/entities/user.entity';
import { Organization } from '../../organizations/entities/organization.entity';
import { EmployeeProfile } from './employee-profile.entity';
import { ProviderRole } from './provider-role.entity';
import { EmployeeRequirementTag } from '../../organizations/hr-files-setup/entities/employee-requirement-tag.entity';

/**
 * The `(user_id, organization_id)` uniqueness used to be a full @Unique()
 * constraint. With soft-delete, we need that constraint to only apply to
 * live rows (deleted_at IS NULL) so HR can re-hire a previously-terminated
 * employee without violating uniqueness. The migration drops the hard
 * constraint and creates a partial unique index instead; TypeORM doesn't
 * model partial indexes as decorators, so it lives only in SQL.
 */
@Entity('employees')
@Index(['user_id'])
@Index(['organization_id'])
@Index(['status'])
@Index(['organization_id', 'status'])
@Index(['provider_role_id'])
@Index(['employment_type'])
@Index(['deleted_at'])
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

  /** Soft-delete marker. Null = active; non-null = the employee has been
   *  terminated/removed from this org but the row is kept for audit. All
   *  employee reads filter `WHERE deleted_at IS NULL`. */
  @DeleteDateColumn({ type: 'timestamptz', nullable: true })
  deleted_at: Date | null;

  /** User id of the admin/HR who performed the soft-delete. */
  @Column({ type: 'uuid', nullable: true })
  deleted_by: string | null;

  /** Free-text reason captured at delete time (e.g. "resigned",
   *  "contract ended", "terminated for cause"). */
  @Column({ type: 'text', nullable: true })
  deletion_reason: string | null;

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

  @OneToMany(() => EmployeeRequirementTag, (ert) => ert.employee)
  employeeRequirementTags?: EmployeeRequirementTag[];
}
