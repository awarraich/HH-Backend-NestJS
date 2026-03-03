import {
  MigrationInterface,
  QueryRunner,
  Table,
  TableIndex,
  TableForeignKey,
} from 'typeorm';

export class CreatePatientChatTables20260302000000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: 'patient_chat_conversations',
        columns: [
          { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
          { name: 'organization_id', type: 'uuid', isNullable: true },
          { name: 'patient_id', type: 'uuid', isNullable: true },
          { name: 'recipient_type', type: 'varchar', length: '50', isNullable: false },
          { name: 'recipient_entity_id', type: 'uuid', isNullable: true },
          { name: 'recipient_display_name', type: 'varchar', length: '255', isNullable: false },
          { name: 'recipient_role', type: 'varchar', length: '255', isNullable: true },
          { name: 'subject', type: 'varchar', length: '500', isNullable: true, default: "'(No subject)'" },
          { name: 'created_at', type: 'timestamptz', default: 'CURRENT_TIMESTAMP' },
          { name: 'updated_at', type: 'timestamptz', default: 'CURRENT_TIMESTAMP' },
        ],
      }),
      true,
    );

    await queryRunner.createForeignKey(
      'patient_chat_conversations',
      new TableForeignKey({
        columnNames: ['organization_id'],
        referencedTableName: 'organizations',
        referencedColumnNames: ['id'],
        onDelete: 'SET NULL',
        name: 'fk_patient_chat_conversations_organization_id',
      }),
    );
    await queryRunner.createForeignKey(
      'patient_chat_conversations',
      new TableForeignKey({
        columnNames: ['patient_id'],
        referencedTableName: 'patients',
        referencedColumnNames: ['id'],
        onDelete: 'SET NULL',
        name: 'fk_patient_chat_conversations_patient_id',
      }),
    );
    await queryRunner.createIndex(
      'patient_chat_conversations',
      new TableIndex({
        name: 'idx_patient_chat_conversations_organization_updated',
        columnNames: ['organization_id', 'updated_at'],
      }),
    );
    await queryRunner.createIndex(
      'patient_chat_conversations',
      new TableIndex({
        name: 'idx_patient_chat_conversations_patient_updated',
        columnNames: ['patient_id', 'updated_at'],
      }),
    );

    await queryRunner.createTable(
      new Table({
        name: 'patient_chat_messages',
        columns: [
          { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
          { name: 'conversation_id', type: 'uuid', isNullable: false },
          { name: 'sender_user_id', type: 'uuid', isNullable: false },
          { name: 'body', type: 'text', isNullable: false },
          { name: 'created_at', type: 'timestamptz', default: 'CURRENT_TIMESTAMP' },
        ],
      }),
      true,
    );

    await queryRunner.createForeignKey(
      'patient_chat_messages',
      new TableForeignKey({
        columnNames: ['conversation_id'],
        referencedTableName: 'patient_chat_conversations',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_patient_chat_messages_conversation_id',
      }),
    );
    await queryRunner.createForeignKey(
      'patient_chat_messages',
      new TableForeignKey({
        columnNames: ['sender_user_id'],
        referencedTableName: 'users',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_patient_chat_messages_sender_user_id',
      }),
    );
    await queryRunner.createIndex(
      'patient_chat_messages',
      new TableIndex({
        name: 'idx_patient_chat_messages_conversation_created',
        columnNames: ['conversation_id', 'created_at'],
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropTable('patient_chat_messages');
    await queryRunner.dropTable('patient_chat_conversations');
  }
}
