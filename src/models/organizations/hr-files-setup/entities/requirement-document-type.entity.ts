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
import { HrDocumentType } from './hr-document-type.entity';

@Entity('requirement_document_types')
@Unique(['requirement_tag_id', 'document_type_id'])
@Index(['requirement_tag_id'])
@Index(['document_type_id'])
export class RequirementDocumentType {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  requirement_tag_id: string;

  @Column({ type: 'uuid' })
  document_type_id: string;

  @CreateDateColumn({ type: 'timestamp with time zone', default: () => 'NOW()' })
  created_at: Date;

  @ManyToOne(() => RequirementTag, (rt) => rt.requirementDocumentTypes, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'requirement_tag_id' })
  requirementTag: RequirementTag;

  @ManyToOne(() => HrDocumentType, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'document_type_id' })
  documentType: HrDocumentType;
}
