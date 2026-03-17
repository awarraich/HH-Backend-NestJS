import { MigrationInterface, QueryRunner } from 'typeorm';

export class ConvertPdfColumnsToPdfFilesJsonb20260319300000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE inservice_trainings ADD COLUMN pdf_files jsonb NOT NULL DEFAULT '[]'`,
    );

    await queryRunner.query(
      `UPDATE inservice_trainings
       SET pdf_files = jsonb_build_array(jsonb_build_object(
         'file_name', pdf_file_name,
         'file_path', pdf_file_path,
         'file_size_bytes', pdf_file_size_bytes
       ))
       WHERE pdf_file_path IS NOT NULL AND pdf_file_path != 'pending'`,
    );

    await queryRunner.query(
      `ALTER TABLE inservice_trainings DROP CONSTRAINT IF EXISTS chk_inservice_trainings_content`,
    );

    await queryRunner.query(`ALTER TABLE inservice_trainings DROP COLUMN pdf_file_name`);
    await queryRunner.query(`ALTER TABLE inservice_trainings DROP COLUMN pdf_file_path`);
    await queryRunner.query(`ALTER TABLE inservice_trainings DROP COLUMN pdf_file_size_bytes`);

    await queryRunner.query(
      `ALTER TABLE inservice_trainings ADD CONSTRAINT chk_inservice_trainings_content
       CHECK (pdf_files != '[]'::jsonb OR video_urls != '[]'::jsonb)`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE inservice_trainings DROP CONSTRAINT IF EXISTS chk_inservice_trainings_content`,
    );

    await queryRunner.query(
      `ALTER TABLE inservice_trainings ADD COLUMN pdf_file_name varchar(255)`,
    );
    await queryRunner.query(
      `ALTER TABLE inservice_trainings ADD COLUMN pdf_file_path varchar(500)`,
    );
    await queryRunner.query(
      `ALTER TABLE inservice_trainings ADD COLUMN pdf_file_size_bytes bigint`,
    );

    await queryRunner.query(
      `UPDATE inservice_trainings
       SET pdf_file_name = pdf_files->0->>'file_name',
           pdf_file_path = pdf_files->0->>'file_path',
           pdf_file_size_bytes = (pdf_files->0->>'file_size_bytes')::bigint
       WHERE pdf_files != '[]'::jsonb`,
    );

    await queryRunner.query(`ALTER TABLE inservice_trainings DROP COLUMN pdf_files`);

    await queryRunner.query(
      `ALTER TABLE inservice_trainings ADD CONSTRAINT chk_inservice_trainings_content
       CHECK (pdf_file_path IS NOT NULL OR video_urls != '[]'::jsonb)`,
    );
  }
}
