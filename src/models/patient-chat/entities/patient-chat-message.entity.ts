import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
  CreateDateColumn,
  Index,
} from 'typeorm';
import { User } from '../../../authentication/entities/user.entity';
import { PatientChatConversation } from './patient-chat-conversation.entity';

@Entity('patient_chat_messages')
@Index(['conversation_id', 'created_at'])
export class PatientChatMessage {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  conversation_id: string;

  @Column({ type: 'uuid' })
  sender_user_id: string;

  @Column({ type: 'text' })
  body: string;

  @CreateDateColumn({ type: 'timestamptz', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;

  @ManyToOne(() => PatientChatConversation, (conv) => conv.messages, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'conversation_id' })
  conversation: PatientChatConversation;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'sender_user_id' })
  senderUser: User;
}
