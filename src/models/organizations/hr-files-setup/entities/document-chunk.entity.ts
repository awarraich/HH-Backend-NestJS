import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
  CreateDateColumn,
  Index,
} from 'typeorm';
import { EmployeeDocument } from './employee-document.entity';

@Entity('document_chunks')
@Index(['document_id'])
@Index(['organization_id'])
@Index(['employee_id'])
export class DocumentChunk {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  document_id: string;

  @Column({ type: 'uuid' })
  organization_id: string;

  @Column({ type: 'uuid' })
  employee_id: string;

  @Column({ type: 'integer' })
  chunk_index: number;

  @Column({ type: 'text' })
  chunk_text: string;

  @Column({ type: 'integer', nullable: true })
  chunk_tokens: number | null;

  @Column({ type: 'jsonb', default: {} })
  metadata: Record<string, unknown>;

  @CreateDateColumn({ type: 'timestamp with time zone', default: () => 'NOW()' })
  created_at: Date;

  @ManyToOne(() => EmployeeDocument, (doc) => doc.chunks, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'document_id' })
  document: EmployeeDocument;
}
