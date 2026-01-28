import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
  OneToMany,
} from 'typeorm';
import { UserRole } from './user-role.entity';

@Entity('users')
@Index(['email'], { unique: true })
@Index(['email_verification_token'])
@Index(['password_reset_token'])
@Index(['is_active'])
@Index(['email_verified'])
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'varchar', length: 255 })
  firstName: string;

  @Column({ type: 'varchar', length: 255 })
  lastName: string;

  @Column({ type: 'varchar', length: 254, unique: true })
  email: string;

  @Column({ type: 'varchar', length: 128, select: false })
  password: string;

  @Column({ type: 'boolean', default: true })
  is_active: boolean;

  @Column({ type: 'boolean', default: false })
  email_verified: boolean;

  @Column({ type: 'varchar', length: 100, nullable: true })
  email_verification_token: string | null;

  @Column({ type: 'timestamp', nullable: true })
  email_verification_sent_at: Date | null;

  @Column({ type: 'varchar', length: 100, nullable: true })
  password_reset_token: string | null;

  @Column({ type: 'timestamp', nullable: true })
  password_reset_sent_at: Date | null;

  @Column({ type: 'boolean', default: false })
  is_two_fa_enabled: boolean;

  @Column({ type: 'text', nullable: true, select: false })
  totp_secret: string | null;

  @Column({ type: 'timestamp', nullable: true })
  totp_secret_created_at: Date | null;

  @Column({ type: 'timestamp', nullable: true })
  last_2fa_verified_at: Date | null;

  @Column({ type: 'timestamp', nullable: true })
  last_login: Date | null;

  // HIPAA Compliance: Audit fields
  @CreateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  updated_at: Date;

  // Relations
  @OneToMany(() => UserRole, (userRole) => userRole.user)
  userRoles: UserRole[];
}
