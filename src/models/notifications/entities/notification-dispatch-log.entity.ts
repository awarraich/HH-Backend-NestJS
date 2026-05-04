import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  Unique,
  Index,
} from 'typeorm';

export type NotificationChannel = 'google_chat' | 'email';
export type DispatchStatus = 'sent' | 'failed' | 'skipped';
export type ReminderKind = '60d' | '30d' | '14d' | '7d' | '1d' | 'expired';

@Entity('notification_dispatch_log')
@Unique(['user_id', 'document_id', 'reminder_kind', 'channel'])
@Index(['user_id'])
@Index(['org_id'])
@Index(['sent_at'])
export class NotificationDispatchLog {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  org_id: string;

  @Column({ type: 'uuid' })
  user_id: string;

  @Column({ type: 'uuid' })
  document_id: string;

  @Column({ type: 'varchar', length: 64 })
  document_type: string;

  @Column({ type: 'varchar', length: 32 })
  reminder_kind: ReminderKind;

  @Column({ type: 'varchar', length: 16 })
  channel: NotificationChannel;

  @Column({ type: 'varchar', length: 16 })
  status: DispatchStatus;

  @Column({ type: 'text', nullable: true })
  error: string | null;

  @CreateDateColumn({ type: 'timestamp with time zone', name: 'sent_at' })
  sent_at: Date;
}
