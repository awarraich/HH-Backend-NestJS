import { MigrationInterface, QueryRunner, Table, TableForeignKey } from 'typeorm';

export class CreateNotificationDispatchLog20260501200002 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: 'notification_dispatch_log',
        columns: [
          {
            name: 'id',
            type: 'uuid',
            isPrimary: true,
            default: 'gen_random_uuid()',
          },
          { name: 'org_id', type: 'uuid', isNullable: false },
          { name: 'user_id', type: 'uuid', isNullable: false },
          { name: 'document_id', type: 'uuid', isNullable: false },
          { name: 'document_type', type: 'varchar', length: '64', isNullable: false },
          { name: 'reminder_kind', type: 'varchar', length: '32', isNullable: false },
          { name: 'channel', type: 'varchar', length: '16', isNullable: false },
          { name: 'status', type: 'varchar', length: '16', isNullable: false },
          { name: 'error', type: 'text', isNullable: true },
          {
            name: 'sent_at',
            type: 'timestamp with time zone',
            default: 'CURRENT_TIMESTAMP',
            isNullable: false,
          },
        ],
        uniques: [
          {
            name: 'uq_notification_dispatch_log_idempotency',
            columnNames: ['user_id', 'document_id', 'reminder_kind', 'channel'],
          },
        ],
        checks: [
          {
            name: 'notification_dispatch_log_channel_values',
            expression: "channel IN ('google_chat', 'email')",
          },
          {
            name: 'notification_dispatch_log_status_values',
            expression: "status IN ('sent', 'failed', 'skipped')",
          },
        ],
      }),
      true,
    );

    await queryRunner.createForeignKey(
      'notification_dispatch_log',
      new TableForeignKey({
        name: 'fk_notification_dispatch_log_user',
        columnNames: ['user_id'],
        referencedTableName: 'users',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
      }),
    );

    await queryRunner.createForeignKey(
      'notification_dispatch_log',
      new TableForeignKey({
        name: 'fk_notification_dispatch_log_org',
        columnNames: ['org_id'],
        referencedTableName: 'organizations',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
      }),
    );

    await queryRunner.query(
      `CREATE INDEX idx_notification_dispatch_log_user_id ON notification_dispatch_log (user_id)`,
    );
    await queryRunner.query(
      `CREATE INDEX idx_notification_dispatch_log_org_id ON notification_dispatch_log (org_id)`,
    );
    await queryRunner.query(
      `CREATE INDEX idx_notification_dispatch_log_sent_at ON notification_dispatch_log (sent_at)`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('DROP INDEX IF EXISTS idx_notification_dispatch_log_sent_at');
    await queryRunner.query('DROP INDEX IF EXISTS idx_notification_dispatch_log_org_id');
    await queryRunner.query('DROP INDEX IF EXISTS idx_notification_dispatch_log_user_id');
    await queryRunner.dropTable('notification_dispatch_log');
  }
}
