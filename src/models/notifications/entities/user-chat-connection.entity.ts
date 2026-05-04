import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  Unique,
  Index,
} from 'typeorm';

export type ChatConnectionProvider = 'google_chat';
export type ChatConnectionStatus = 'pending' | 'connected' | 'revoked';

@Entity('user_chat_connections')
@Unique(['user_id', 'provider'])
@Index(['user_id'])
@Index(['org_id'])
@Index(['status'])
export class UserChatConnection {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  user_id: string;

  @Column({ type: 'uuid' })
  org_id: string;

  @Column({ type: 'varchar', length: 32 })
  provider: ChatConnectionProvider;

  @Column({ type: 'varchar', length: 255, nullable: true })
  chat_user_id: string | null;

  @Column({ type: 'varchar', length: 255, nullable: true })
  dm_space_name: string | null;

  @Column({ type: 'varchar', length: 16, default: 'pending' })
  status: ChatConnectionStatus;

  @Column({ type: 'boolean', default: true })
  chat_eligible: boolean;

  @Column({ type: 'timestamp with time zone', nullable: true })
  connected_at: Date | null;

  @Column({ type: 'timestamp with time zone', nullable: true })
  revoked_at: Date | null;

  @CreateDateColumn({ type: 'timestamp with time zone' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamp with time zone' })
  updated_at: Date;
}
