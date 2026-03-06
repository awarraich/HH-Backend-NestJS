import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
} from 'typeorm';
import { InserviceTraining } from './inservice-training.entity';

export const INSERVICE_QUESTION_TYPES = [
  'multiple_choice',
  'true_false',
  'fill_blank',
  'short_answer',
  'match',
] as const;

export type InserviceQuestionType =
  (typeof INSERVICE_QUESTION_TYPES)[number];

@Entity('inservice_quiz_questions')
@Index(['inservice_training_id'])
@Index(['inservice_training_id', 'sort_order'])
export class InserviceQuizQuestion {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  inservice_training_id: string;

  @Column({ type: 'integer', default: 0 })
  sort_order: number;

  @Column({ type: 'varchar', length: 30 })
  question_type: string;

  @Column({ type: 'text' })
  question_text: string;

  @Column({ type: 'jsonb', nullable: true })
  options: string[] | null;

  @Column({ type: 'integer', nullable: true })
  correct_answer_index: number | null;

  @Column({ type: 'boolean', nullable: true })
  correct_boolean: boolean | null;

  @Column({ type: 'text', nullable: true })
  correct_text: string | null;

  @Column({ type: 'text', nullable: true })
  sample_answer: string | null;

  @Column({ type: 'jsonb', nullable: true })
  left_column: unknown;

  @Column({ type: 'jsonb', nullable: true })
  right_column: unknown;

  @Column({ type: 'jsonb', nullable: true })
  correct_matches: unknown;

  @Column({ type: 'text', nullable: true })
  explanation: string | null;

  @CreateDateColumn({ type: 'timestamp with time zone', default: () => 'NOW()' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamp with time zone', default: () => 'NOW()' })
  updated_at: Date;

  @ManyToOne(() => InserviceTraining, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'inservice_training_id' })
  inserviceTraining: InserviceTraining;
}
