import {
  MigrationInterface,
  QueryRunner,
  Table,
  TableIndex,
  TableForeignKey,
  TableUnique,
} from 'typeorm';

export class CreateReferralTables20260209000002 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: 'referrals',
        columns: [
          { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
          { name: 'public_id', type: 'varchar', length: '20', isUnique: true },
          { name: 'organization_type_id', type: 'smallint', isNullable: false },
          { name: 'status', type: 'varchar', length: '20', isNullable: false },
          { name: 'urgency', type: 'varchar', length: '20', isNullable: false },
          { name: 'patient_id', type: 'uuid', isNullable: false },
          { name: 'sending_organization_id', type: 'uuid', isNullable: false },
          { name: 'insurance_provider', type: 'varchar', length: '200', isNullable: true },
          { name: 'estimated_cost', type: 'varchar', length: '50', isNullable: true },
          { name: 'notes', type: 'text', isNullable: false },
          { name: 'level_of_care', type: 'varchar', length: '30', isNullable: true },
          { name: 'date_responded', type: 'timestamp', isNullable: true },
          { name: 'selected_organization_id', type: 'uuid', isNullable: true },
          { name: 'created_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP' },
          { name: 'updated_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP' },
        ],
      }),
      true,
    );

    await queryRunner.createForeignKey(
      'referrals',
      new TableForeignKey({
        columnNames: ['organization_type_id'],
        referencedTableName: 'organization_types',
        referencedColumnNames: ['id'],
        onDelete: 'RESTRICT',
        name: 'fk_referrals_organization_type_id',
      }),
    );
    await queryRunner.createForeignKey(
      'referrals',
      new TableForeignKey({
        columnNames: ['patient_id'],
        referencedTableName: 'patients',
        referencedColumnNames: ['id'],
        onDelete: 'RESTRICT',
        name: 'fk_referrals_patient_id',
      }),
    );
    await queryRunner.createForeignKey(
      'referrals',
      new TableForeignKey({
        columnNames: ['sending_organization_id'],
        referencedTableName: 'organizations',
        referencedColumnNames: ['id'],
        onDelete: 'RESTRICT',
        name: 'fk_referrals_sending_organization_id',
      }),
    );
    await queryRunner.createForeignKey(
      'referrals',
      new TableForeignKey({
        columnNames: ['selected_organization_id'],
        referencedTableName: 'organizations',
        referencedColumnNames: ['id'],
        onDelete: 'SET NULL',
        name: 'fk_referrals_selected_organization_id',
      }),
    );

    await queryRunner.createIndex(
      'referrals',
      new TableIndex({ name: 'idx_referrals_sending_organization_id', columnNames: ['sending_organization_id'] }),
    );
    await queryRunner.createIndex(
      'referrals',
      new TableIndex({ name: 'idx_referrals_patient_id', columnNames: ['patient_id'] }),
    );
    await queryRunner.createIndex(
      'referrals',
      new TableIndex({ name: 'idx_referrals_status', columnNames: ['status'] }),
    );
    await queryRunner.createIndex(
      'referrals',
      new TableIndex({ name: 'idx_referrals_organization_type_id', columnNames: ['organization_type_id'] }),
    );
    await queryRunner.createIndex(
      'referrals',
      new TableIndex({ name: 'idx_referrals_created_at', columnNames: ['created_at'] }),
    );

    await queryRunner.createTable(
      new Table({
        name: 'referral_organizations',
        columns: [
          { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
          { name: 'referral_id', type: 'uuid', isNullable: false },
          { name: 'organization_id', type: 'uuid', isNullable: false },
          { name: 'response_status', type: 'varchar', length: '20', isNullable: false },
          { name: 'response_date', type: 'timestamp', isNullable: true },
          { name: 'proposed_terms', type: 'text', isNullable: true },
          { name: 'notes', type: 'text', isNullable: true },
          { name: 'assignment_outcome', type: 'varchar', length: '20', isNullable: true },
          { name: 'created_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP' },
          { name: 'updated_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP' },
        ],
      }),
      true,
    );

    await queryRunner.createUniqueConstraint(
      'referral_organizations',
      new TableUnique({ columnNames: ['referral_id', 'organization_id'], name: 'uq_referral_organizations_referral_org' }),
    );
    await queryRunner.createForeignKey(
      'referral_organizations',
      new TableForeignKey({
        columnNames: ['referral_id'],
        referencedTableName: 'referrals',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_referral_organizations_referral_id',
      }),
    );
    await queryRunner.createForeignKey(
      'referral_organizations',
      new TableForeignKey({
        columnNames: ['organization_id'],
        referencedTableName: 'organizations',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_referral_organizations_organization_id',
      }),
    );
    await queryRunner.createIndex(
      'referral_organizations',
      new TableIndex({ name: 'idx_referral_organizations_referral_id', columnNames: ['referral_id'] }),
    );
    await queryRunner.createIndex(
      'referral_organizations',
      new TableIndex({ name: 'idx_referral_organizations_organization_id', columnNames: ['organization_id'] }),
    );

    await queryRunner.createTable(
      new Table({
        name: 'referral_messages',
        columns: [
          { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
          { name: 'referral_id', type: 'uuid', isNullable: false },
          { name: 'receiver_organization_id', type: 'uuid', isNullable: true },
          { name: 'sender_user_id', type: 'uuid', isNullable: true },
          { name: 'sender_organization_id', type: 'uuid', isNullable: true },
          { name: 'message', type: 'text', isNullable: false },
          { name: 'is_system', type: 'boolean', default: false },
          { name: 'created_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP' },
        ],
      }),
      true,
    );

    await queryRunner.createForeignKey(
      'referral_messages',
      new TableForeignKey({
        columnNames: ['referral_id'],
        referencedTableName: 'referrals',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_referral_messages_referral_id',
      }),
    );
    await queryRunner.createForeignKey(
      'referral_messages',
      new TableForeignKey({
        columnNames: ['receiver_organization_id'],
        referencedTableName: 'organizations',
        referencedColumnNames: ['id'],
        onDelete: 'SET NULL',
        name: 'fk_referral_messages_receiver_organization_id',
      }),
    );
    await queryRunner.createForeignKey(
      'referral_messages',
      new TableForeignKey({
        columnNames: ['sender_user_id'],
        referencedTableName: 'users',
        referencedColumnNames: ['id'],
        onDelete: 'SET NULL',
        name: 'fk_referral_messages_sender_user_id',
      }),
    );
    await queryRunner.createForeignKey(
      'referral_messages',
      new TableForeignKey({
        columnNames: ['sender_organization_id'],
        referencedTableName: 'organizations',
        referencedColumnNames: ['id'],
        onDelete: 'SET NULL',
        name: 'fk_referral_messages_sender_organization_id',
      }),
    );
    await queryRunner.createIndex(
      'referral_messages',
      new TableIndex({ name: 'idx_referral_messages_referral_created', columnNames: ['referral_id', 'created_at'] }),
    );

    await queryRunner.createTable(
      new Table({
        name: 'referral_last_read',
        columns: [
          { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
          { name: 'referral_id', type: 'uuid', isNullable: false },
          { name: 'organization_id', type: 'uuid', isNullable: false },
          { name: 'last_read_at', type: 'timestamp', isNullable: false },
          { name: 'created_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP' },
          { name: 'updated_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP' },
        ],
      }),
      true,
    );

    await queryRunner.createUniqueConstraint(
      'referral_last_read',
      new TableUnique({ columnNames: ['referral_id', 'organization_id'], name: 'uq_referral_last_read_referral_org' }),
    );
    await queryRunner.createForeignKey(
      'referral_last_read',
      new TableForeignKey({
        columnNames: ['referral_id'],
        referencedTableName: 'referrals',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_referral_last_read_referral_id',
      }),
    );
    await queryRunner.createForeignKey(
      'referral_last_read',
      new TableForeignKey({
        columnNames: ['organization_id'],
        referencedTableName: 'organizations',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_referral_last_read_organization_id',
      }),
    );
    await queryRunner.createIndex(
      'referral_last_read',
      new TableIndex({ name: 'idx_referral_last_read_referral_id', columnNames: ['referral_id'] }),
    );
    await queryRunner.createIndex(
      'referral_last_read',
      new TableIndex({ name: 'idx_referral_last_read_organization_id', columnNames: ['organization_id'] }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropTable('referral_last_read');
    await queryRunner.dropTable('referral_messages');
    await queryRunner.dropTable('referral_organizations');
    await queryRunner.dropTable('referrals');
  }
}
