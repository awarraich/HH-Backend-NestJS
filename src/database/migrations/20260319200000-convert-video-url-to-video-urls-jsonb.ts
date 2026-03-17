import { MigrationInterface, QueryRunner } from 'typeorm';

export class ConvertVideoUrlToVideoUrlsJsonb20260319200000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE inservice_trainings ADD COLUMN video_urls jsonb NOT NULL DEFAULT '[]'`,
    );

    await queryRunner.query(
      `UPDATE inservice_trainings SET video_urls = jsonb_build_array(video_url) WHERE video_url IS NOT NULL`,
    );

    await queryRunner.query(
      `ALTER TABLE inservice_trainings DROP CONSTRAINT IF EXISTS chk_inservice_trainings_content`,
    );

    await queryRunner.query(`ALTER TABLE inservice_trainings DROP COLUMN video_url`);

    await queryRunner.query(
      `ALTER TABLE inservice_trainings ADD CONSTRAINT chk_inservice_trainings_content
       CHECK (pdf_file_path IS NOT NULL OR video_urls != '[]'::jsonb)`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE inservice_trainings DROP CONSTRAINT IF EXISTS chk_inservice_trainings_content`,
    );

    await queryRunner.query(
      `ALTER TABLE inservice_trainings ADD COLUMN video_url varchar(2048)`,
    );

    await queryRunner.query(
      `UPDATE inservice_trainings SET video_url = video_urls->>0 WHERE video_urls != '[]'::jsonb`,
    );

    await queryRunner.query(`ALTER TABLE inservice_trainings DROP COLUMN video_urls`);

    await queryRunner.query(
      `ALTER TABLE inservice_trainings ADD CONSTRAINT chk_inservice_trainings_content
       CHECK (pdf_file_path IS NOT NULL OR video_url IS NOT NULL)`,
    );
  }
}
