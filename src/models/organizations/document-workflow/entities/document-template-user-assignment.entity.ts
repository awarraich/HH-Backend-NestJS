import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  Index,
  Unique,
  ManyToOne,
  JoinColumn,
} from 'typeorm';
import { CompetencyTemplate } from './competency-template.entity';
import { DocumentWorkflowRole } from './document-workflow-role.entity';

@Entity('document_template_user_assignments')
@Index(['template_id'])
@Index(['user_id'])
@Index(['template_id', 'user_id'])
@Unique(['template_id', 'user_id', 'role_id'])
export class DocumentTemplateUserAssignment {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  template_id: string;

  @Column({ type: 'uuid' })
  user_id: string;

  @Column({ type: 'uuid' })
  role_id: string;

  @Column({ type: 'uuid', nullable: true })
  assigned_by: string | null;

  @CreateDateColumn({ type: 'timestamptz', default: () => 'now()' })
  created_at: Date;

  @ManyToOne(() => CompetencyTemplate, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'template_id' })
  template: CompetencyTemplate;

  @ManyToOne(() => DocumentWorkflowRole, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'role_id' })
  role: DocumentWorkflowRole;
}
