import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  Unique,
  Index,
} from 'typeorm';

export type IntegrationProvider = 'google_chat';
export type IntegrationStatus = 'pending' | 'active' | 'disabled';

@Entity('organization_integrations')
@Unique(['org_id', 'provider'])
@Index(['org_id'])
@Index(['status'])
export class OrganizationIntegration {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  org_id: string;

  @Column({ type: 'varchar', length: 32 })
  provider: IntegrationProvider;

  @Column({ type: 'varchar', length: 16, default: 'pending' })
  status: IntegrationStatus;

  @Column({ type: 'varchar', length: 255, nullable: true })
  workspace_domain: string | null;

  @Column({ type: 'jsonb', nullable: true })
  config: Record<string, unknown> | null;

  @Column({ type: 'uuid', nullable: true })
  enabled_by_user_id: string | null;

  @Column({ type: 'timestamp with time zone', nullable: true })
  enabled_at: Date | null;

  @Column({ type: 'timestamp with time zone', nullable: true })
  verified_at: Date | null;

  @Column({ type: 'timestamp with time zone', nullable: true })
  disabled_at: Date | null;

  @CreateDateColumn({ type: 'timestamp with time zone' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamp with time zone' })
  updated_at: Date;
}
