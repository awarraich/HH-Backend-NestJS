import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  OneToMany,
  JoinColumn,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
} from 'typeorm';
import { Organization } from '../../entities/organization.entity';
import { RequirementDocumentType } from './requirement-document-type.entity';
import { RequirementInserviceTraining } from './requirement-inservice-training.entity';
import { RequirementDocumentTemplate } from './requirement-document-template.entity';

@Entity('requirement_tags')
@Index(['organization_id'])
@Index(['organization_id', 'category'])
export class RequirementTag {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  organization_id: string;

  @Column({ type: 'varchar', length: 255 })
  title: string;

  @Column({ type: 'varchar', length: 100 })
  category: string;

  @CreateDateColumn({ type: 'timestamp with time zone', default: () => 'NOW()' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamp with time zone', default: () => 'NOW()' })
  updated_at: Date;

  @ManyToOne(() => Organization, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'organization_id' })
  organization: Organization;

  @OneToMany(() => RequirementDocumentType, (rdt) => rdt.requirementTag, { cascade: true })
  requirementDocumentTypes: RequirementDocumentType[];

  @OneToMany(() => RequirementInserviceTraining, (rit) => rit.requirementTag, { cascade: true })
  requirementInserviceTrainings: RequirementInserviceTraining[];

  @OneToMany(() => RequirementDocumentTemplate, (rdt) => rdt.requirementTag, { cascade: true })
  requirementDocumentTemplates: RequirementDocumentTemplate[];
}
