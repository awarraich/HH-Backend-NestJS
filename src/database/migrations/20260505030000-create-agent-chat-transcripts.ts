import { MigrationInterface, QueryRunner, Table, TableForeignKey } from 'typeorm';

export class CreateAgentChatTranscripts20260505030000
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: 'agent_chat_transcripts',
        columns: [
          {
            name: 'id',
            type: 'bigserial',
            isPrimary: true,
          },
          { name: 'organization_id', type: 'uuid', isNullable: false },
          { name: 'user_id', type: 'uuid', isNullable: false },
          { name: 'chat_thread_name', type: 'text', isNullable: false },
          { name: 'turn_index', type: 'int', isNullable: false },
          { name: 'role', type: 'varchar', length: '20', isNullable: false },
          { name: 'tool_name', type: 'varchar', length: '64', isNullable: true },
          { name: 'payload', type: 'jsonb', isNullable: false },
          { name: 'tokens_in', type: 'int', isNullable: true },
          { name: 'tokens_out', type: 'int', isNullable: true },
          {
            name: 'cost_usd',
            type: 'numeric',
            precision: 10,
            scale: 6,
            isNullable: true,
          },
          {
            name: 'counts_against_quota',
            type: 'boolean',
            isNullable: false,
            default: true,
          },
          {
            name: 'created_at',
            type: 'timestamp with time zone',
            default: 'CURRENT_TIMESTAMP',
            isNullable: false,
          },
        ],
        uniques: [
          {
            name: 'uq_agent_chat_transcripts_thread_turn',
            columnNames: ['chat_thread_name', 'turn_index'],
          },
        ],
        checks: [
          {
            name: 'agent_chat_transcripts_role_values',
            expression:
              "role IN ('user', 'assistant', 'tool', 'system')",
          },
        ],
      }),
      true,
    );

    await queryRunner.createForeignKey(
      'agent_chat_transcripts',
      new TableForeignKey({
        name: 'fk_agent_chat_transcripts_user',
        columnNames: ['user_id'],
        referencedTableName: 'users',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
      }),
    );

    await queryRunner.createForeignKey(
      'agent_chat_transcripts',
      new TableForeignKey({
        name: 'fk_agent_chat_transcripts_org',
        columnNames: ['organization_id'],
        referencedTableName: 'organizations',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
      }),
    );

    await queryRunner.query(
      `CREATE INDEX idx_agent_chat_transcripts_org_user_created
       ON agent_chat_transcripts (organization_id, user_id, created_at DESC)`,
    );
    await queryRunner.query(
      `CREATE INDEX idx_agent_chat_transcripts_thread
       ON agent_chat_transcripts (chat_thread_name, turn_index)`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `DROP INDEX IF EXISTS idx_agent_chat_transcripts_thread`,
    );
    await queryRunner.query(
      `DROP INDEX IF EXISTS idx_agent_chat_transcripts_org_user_created`,
    );
    await queryRunner.dropTable('agent_chat_transcripts');
  }
}
