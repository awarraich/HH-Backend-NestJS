import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
  CreateDateColumn,
  Index,
} from 'typeorm';
import { Referral } from './referral.entity';
import { Organization } from './organization.entity';
import { User } from '../../../authentication/entities/user.entity';

@Entity('referral_messages')
@Index(['referral_id', 'created_at'])
export class ReferralMessage {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  referral_id: string;

  @Column({ type: 'uuid', nullable: true })
  receiver_organization_id: string | null;

  @Column({ type: 'uuid', nullable: true })
  sender_user_id: string | null;

  @Column({ type: 'uuid', nullable: true })
  sender_organization_id: string | null;

  @Column({ type: 'text' })
  message: string;

  @Column({ type: 'boolean', default: false })
  is_system: boolean;

  @CreateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;

  @ManyToOne(() => Referral, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'referral_id' })
  referral: Referral;

  @ManyToOne(() => Organization, { onDelete: 'SET NULL' })
  @JoinColumn({ name: 'receiver_organization_id' })
  receiverOrganization: Organization | null;

  @ManyToOne(() => User, { onDelete: 'SET NULL' })
  @JoinColumn({ name: 'sender_user_id' })
  senderUser: User | null;

  @ManyToOne(() => Organization, { onDelete: 'SET NULL' })
  @JoinColumn({ name: 'sender_organization_id' })
  senderOrganization: Organization | null;
}
