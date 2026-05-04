import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  Index,
  Unique,
} from 'typeorm';

export type TranscriptRole = 'user' | 'assistant' | 'tool' | 'system';

@Entity('agent_chat_transcripts')
@Unique(['chat_thread_name', 'turn_index'])
@Index(['organization_id', 'user_id', 'created_at'])
@Index(['chat_thread_name', 'turn_index'])
export class AgentChatTranscript {
  @PrimaryGeneratedColumn('increment', { type: 'bigint' })
  id: string;

  @Column({ type: 'uuid' })
  organization_id: string;

  @Column({ type: 'uuid' })
  user_id: string;

  @Column({ type: 'text' })
  chat_thread_name: string;

  @Column({ type: 'int' })
  turn_index: number;

  @Column({ type: 'varchar', length: 20 })
  role: TranscriptRole;

  @Column({ type: 'varchar', length: 64, nullable: true })
  tool_name: string | null;

  @Column({ type: 'jsonb' })
  payload: Record<string, unknown>;

  @Column({ type: 'int', nullable: true })
  tokens_in: number | null;

  @Column({ type: 'int', nullable: true })
  tokens_out: number | null;

  @Column({
    type: 'numeric',
    precision: 10,
    scale: 6,
    nullable: true,
    transformer: {
      to: (v: number | null) => v,
      // numeric columns come back as strings from pg; coerce to number for ergonomics.
      from: (v: string | null) => (v === null ? null : Number(v)),
    },
  })
  cost_usd: number | null;

  @Column({ type: 'boolean', default: true })
  counts_against_quota: boolean;

  @CreateDateColumn({ type: 'timestamp with time zone' })
  created_at: Date;
}
