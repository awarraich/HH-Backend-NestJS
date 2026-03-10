import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, Index } from 'typeorm';

@Entity('audit_logs')
@Index(['user_id'])
@Index(['action'])
@Index(['resource_type'])
@Index(['created_at'])
@Index(['user_id', 'created_at'])
export class AuditLog {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid', nullable: true })
  user_id: string;

  @Column({ type: 'varchar', length: 50 })
  action: string; // CREATE | READ | UPDATE | DELETE | LOGIN | LOGOUT | etc.

  @Column({ type: 'varchar', length: 100, nullable: true })
  resource_type: string; // USER | ORGANIZATION | PATIENT | etc.

  @Column({ type: 'uuid', nullable: true })
  resource_id: string;

  @Column({ type: 'text', nullable: true })
  description: string;

  @Column({ type: 'jsonb', nullable: true })
  metadata: Record<string, unknown>; // Additional data (before/after values, IP, etc.)

  @Column({ type: 'varchar', length: 45, nullable: true })
  ip_address: string;

  @Column({ type: 'varchar', length: 500, nullable: true })
  user_agent: string;

  @Column({ type: 'varchar', length: 20, default: 'success' })
  status: string; // SUCCESS | FAILURE | ERROR

  @Column({ type: 'text', nullable: true })
  error_message: string;

  @CreateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;
}
