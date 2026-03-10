import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  OneToMany,
  ManyToOne,
  JoinColumn,
  Index,
} from 'typeorm';
import { Patient } from '../../patients/entities/patient.entity';
import { Organization } from '../../organizations/entities/organization.entity';
import { PatientChatMessage } from './patient-chat-message.entity';

export type RecipientType = 'organization' | 'lab' | 'doctor' | 'clinical' | 'therapist';

@Entity('patient_chat_conversations')
@Index(['organization_id', 'updated_at'])
@Index(['patient_id', 'updated_at'])
export class PatientChatConversation {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid', nullable: true })
  organization_id: string | null;

  @Column({ type: 'uuid', nullable: true })
  patient_id: string | null;

  @Column({ type: 'varchar', length: 50 })
  recipient_type: RecipientType;

  @Column({ type: 'uuid', nullable: true })
  recipient_entity_id: string | null;

  @Column({ type: 'varchar', length: 255 })
  recipient_display_name: string;

  @Column({ type: 'varchar', length: 255, nullable: true })
  recipient_role: string | null;

  @Column({ type: 'varchar', length: 500, default: '(No subject)' })
  subject: string;

  @CreateDateColumn({ type: 'timestamptz', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamptz', default: () => 'CURRENT_TIMESTAMP' })
  updated_at: Date;

  @ManyToOne(() => Organization, { onDelete: 'SET NULL', nullable: true })
  @JoinColumn({ name: 'organization_id' })
  organization: Organization | null;

  @ManyToOne(() => Patient, { onDelete: 'SET NULL', nullable: true })
  @JoinColumn({ name: 'patient_id' })
  patient: Patient | null;

  @OneToMany(() => PatientChatMessage, (msg) => msg.conversation, {
    cascade: true,
  })
  messages: PatientChatMessage[];
}
