import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
} from 'typeorm';

@Entity('competency_templates')
@Index(['organization_id'])
export class CompetencyTemplate {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  organization_id: string;

  @Column({ type: 'varchar', length: 255, default: '' })
  name: string;

  @Column({ type: 'text', default: '' })
  description: string;

  @Column({ type: 'jsonb', default: [] })
  document_fields: Record<string, any>[];

  @Column({ type: 'jsonb', default: [] })
  roles: Record<string, any>[];

  @Column({ type: 'varchar', length: 500, nullable: true })
  pdf_file_key: string | null;

  @Column({ type: 'varchar', length: 255, nullable: true })
  pdf_original_name: string | null;

  @Column({ type: 'integer', nullable: true })
  pdf_size_bytes: number | null;

  @Column({ type: 'uuid', nullable: true })
  created_by: string | null;

  @CreateDateColumn({ type: 'timestamptz', default: () => 'now()' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamptz', default: () => 'now()' })
  updated_at: Date;
}
