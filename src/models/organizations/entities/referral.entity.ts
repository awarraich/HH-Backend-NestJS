import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  ManyToOne,
  OneToMany,
  JoinColumn,
  Index,
} from 'typeorm';
import { Organization } from './organization.entity';
import { OrganizationType } from './organization-type.entity';
import { Patient } from '../../patients/entities/patient.entity';
import { ReferralOrganization } from './referral-organization.entity';
import { ReferralDocument } from './referral-document.entity';

@Entity('referrals')
@Index(['sending_organization_id'])
@Index(['patient_id'])
@Index(['status'])
@Index(['organization_type_id'])
@Index(['created_at'])
export class Referral {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'varchar', length: 20, unique: true })
  public_id: string;

  @Column({ type: 'smallint' })
  organization_type_id: number;

  @Column({ type: 'varchar', length: 20 })
  status: string;

  @Column({ type: 'varchar', length: 20 })
  urgency: string;

  @Column({ type: 'uuid' })
  patient_id: string;

  @Column({ type: 'uuid' })
  sending_organization_id: string;

  @Column({ type: 'varchar', length: 200, nullable: true })
  insurance_provider: string | null;

  @Column({ type: 'varchar', length: 50, nullable: true })
  estimated_cost: string | null;

  @Column({ type: 'text' })
  notes: string;

  @Column({ type: 'varchar', length: 30, nullable: true })
  level_of_care: string | null;

  @Column({ type: 'timestamp', nullable: true })
  date_responded: Date | null;

  @Column({ type: 'uuid', nullable: true })
  selected_organization_id: string | null;

  @CreateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  updated_at: Date;

  @ManyToOne(() => OrganizationType, { onDelete: 'RESTRICT' })
  @JoinColumn({ name: 'organization_type_id' })
  organizationType: OrganizationType;

  @ManyToOne(() => Patient, { onDelete: 'RESTRICT' })
  @JoinColumn({ name: 'patient_id' })
  patient: Patient;

  @ManyToOne(() => Organization, { onDelete: 'RESTRICT' })
  @JoinColumn({ name: 'sending_organization_id' })
  sendingOrganization: Organization;

  @ManyToOne(() => Organization, { onDelete: 'SET NULL' })
  @JoinColumn({ name: 'selected_organization_id' })
  selectedOrganization: Organization | null;

  @OneToMany(() => ReferralOrganization, (ro) => ro.referral)
  referralOrganizations: ReferralOrganization[];

  @OneToMany(() => ReferralDocument, (doc) => doc.referral)
  referralDocuments: ReferralDocument[];
}
