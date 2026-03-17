import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
  OneToMany,
} from 'typeorm';
import { Organization } from '../../entities/organization.entity';
import { Employee } from '../../../employees/entities/employee.entity';
import { HrDocumentType } from './hr-document-type.entity';
import { User } from '../../../../authentication/entities/user.entity';
import { DocumentChunk } from './document-chunk.entity';

@Entity('employee_documents')
@Index(['organization_id'])
@Index(['employee_id'])
@Index(['document_type_id'])
export class EmployeeDocument {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  organization_id: string;

  @Column({ type: 'uuid' })
  employee_id: string;

  @Column({ type: 'uuid' })
  document_type_id: string;

  @Column({ type: 'varchar', length: 255 })
  file_name: string;

  @Column({ type: 'varchar', length: 500 })
  file_path: string;

  @Column({ type: 'bigint', nullable: true })
  file_size_bytes: number | null;

  @Column({ type: 'varchar', length: 100, nullable: true })
  mime_type: string | null;

  @Column({ type: 'uuid', nullable: true })
  uploaded_by: string | null;

  @Column({ type: 'text', nullable: true })
  extracted_text: string | null;

  @Column({ type: 'varchar', length: 20, default: 'pending' })
  extraction_status: string;

  @Column({ type: 'text', nullable: true })
  extraction_error: string | null;

  @CreateDateColumn({ type: 'timestamp with time zone', default: () => 'NOW()' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamp with time zone', default: () => 'NOW()' })
  updated_at: Date;

  @Column({ type: 'timestamp with time zone', nullable: true })
  deleted_at: Date | null;

  @ManyToOne(() => Organization, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'organization_id' })
  organization: Organization;

  @ManyToOne(() => Employee, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'employee_id' })
  employee: Employee;

  @ManyToOne(() => HrDocumentType, { onDelete: 'RESTRICT' })
  @JoinColumn({ name: 'document_type_id' })
  documentType: HrDocumentType;

  @ManyToOne(() => User, { onDelete: 'SET NULL' })
  @JoinColumn({ name: 'uploaded_by' })
  uploadedByUser: User | null;

  @OneToMany(() => DocumentChunk, (chunk) => chunk.document)
  chunks: DocumentChunk[];
}
