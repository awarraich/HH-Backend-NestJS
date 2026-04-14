import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
  CreateDateColumn,
  Index,
  Unique,
} from 'typeorm';
import { RequirementTag } from './requirement-tag.entity';
import { CompetencyTemplate } from '../../document-workflow/entities/competency-template.entity';

@Entity('requirement_document_templates')
@Unique(['requirement_tag_id', 'document_template_id'])
@Index(['requirement_tag_id'])
@Index(['document_template_id'])
export class RequirementDocumentTemplate {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  requirement_tag_id: string;

  @Column({ type: 'uuid' })
  document_template_id: string;

  @CreateDateColumn({ type: 'timestamp with time zone', default: () => 'NOW()' })
  created_at: Date;

  @ManyToOne(() => RequirementTag, (rt) => rt.requirementDocumentTemplates, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'requirement_tag_id' })
  requirementTag: RequirementTag;

  @ManyToOne(() => CompetencyTemplate, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'document_template_id' })
  documentTemplate: CompetencyTemplate;
}
