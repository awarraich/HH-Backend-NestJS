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
import { Referral } from './referral.entity';
import { Organization } from './organization.entity';

@Entity('referral_organizations')
@Unique(['referral_id', 'organization_id'])
@Index(['referral_id'])
@Index(['organization_id'])
export class ReferralOrganization {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  referral_id: string;

  @Column({ type: 'uuid' })
  organization_id: string;

  @Column({ type: 'varchar', length: 20 })
  response_status: string;

  @Column({ type: 'timestamp', nullable: true })
  response_date: Date | null;

  @Column({ type: 'text', nullable: true })
  proposed_terms: string | null;

  @Column({ type: 'text', nullable: true })
  notes: string | null;

  @Column({ type: 'varchar', length: 20, nullable: true })
  assignment_outcome: string | null;

  @CreateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  updated_at: Date;

  @ManyToOne(() => Referral, (r) => r.referralOrganizations, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'referral_id' })
  referral: Referral;

  @ManyToOne(() => Organization, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'organization_id' })
  organization: Organization;
}
