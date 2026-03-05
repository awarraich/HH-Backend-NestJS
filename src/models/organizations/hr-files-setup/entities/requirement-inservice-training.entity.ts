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
import { InserviceTraining } from './inservice-training.entity';

@Entity('requirement_inservice_trainings')
@Unique(['requirement_tag_id', 'inservice_training_id'])
@Index(['requirement_tag_id'])
@Index(['inservice_training_id'])
export class RequirementInserviceTraining {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  requirement_tag_id: string;

  @Column({ type: 'uuid' })
  inservice_training_id: string;

  @CreateDateColumn({ type: 'timestamp with time zone', default: () => 'NOW()' })
  created_at: Date;

  @ManyToOne(() => RequirementTag, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'requirement_tag_id' })
  requirementTag: RequirementTag;

  @ManyToOne(() => InserviceTraining, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'inservice_training_id' })
  inserviceTraining: InserviceTraining;
}
