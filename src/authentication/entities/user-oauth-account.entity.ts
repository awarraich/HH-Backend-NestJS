import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  Unique,
  Index,
} from 'typeorm';

@Entity('user_oauth_accounts')
@Unique(['user_id', 'provider'])
@Index(['user_id'])
export class UserOAuthAccount {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  user_id: string;

  @Column({ type: 'varchar', length: 32 })
  provider: 'google';

  @Column({ type: 'varchar', length: 255, nullable: true })
  provider_account_id: string | null;

  @Column({ type: 'text', nullable: true })
  access_token: string | null;

  @Column({ type: 'text', nullable: true })
  refresh_token: string | null;

  @Column({ type: 'text', nullable: true })
  scope: string | null;

  @Column({ type: 'timestamp with time zone', nullable: true })
  access_token_expires_at: Date | null;

  @CreateDateColumn({ type: 'timestamp with time zone' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamp with time zone' })
  updated_at: Date;
}
