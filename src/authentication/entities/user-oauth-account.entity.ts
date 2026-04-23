import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  Unique,
  Index,
} from 'typeorm';

/**
 * Per-user OAuth token store. A user may have one row per provider
 * (currently only `google`). The refresh_token is what we need long-term —
 * the access_token is just a cache of the last exchange we did and is
 * refreshed on demand when it expires.
 *
 * Why this entity exists: Passport's `validate()` only keeps the access
 * token in memory during the initial sign-in. To call Google Calendar on
 * behalf of the user later (to create a Meet link when they schedule an
 * interview) we need the refresh token persisted.
 */
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

  /** External provider account id (e.g. Google's `sub`). */
  @Column({ type: 'varchar', length: 255, nullable: true })
  provider_account_id: string | null;

  /** Last access token we received. Opaque bearer, expires within an hour. */
  @Column({ type: 'text', nullable: true })
  access_token: string | null;

  /**
   * Refresh token — long-lived. Google only returns this on the first consent
   * (or when `prompt=consent` is re-sent). Treat as a secret; never log.
   */
  @Column({ type: 'text', nullable: true })
  refresh_token: string | null;

  /** Space-delimited scopes granted on the last consent. */
  @Column({ type: 'text', nullable: true })
  scope: string | null;

  @Column({ type: 'timestamp with time zone', nullable: true })
  access_token_expires_at: Date | null;

  @CreateDateColumn({ type: 'timestamp with time zone' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamp with time zone' })
  updated_at: Date;
}
