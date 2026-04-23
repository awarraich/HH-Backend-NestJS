import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as fs from 'fs';
import * as path from 'path';
import { randomUUID } from 'crypto';
import { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } from '@aws-sdk/client-s3';
import { StorageConfigService } from '../../../../config/storage/config.service';

const HR_DOCUMENTS_SUBDIR = 'hr-documents';
const INSERVICE_DOCUMENTS_SUBDIR = 'inservices';

@Injectable()
export class EmployeeDocumentStorageService {
  constructor(private readonly s3: S3Service) {}

  presignUploadForEmployeeDocument(
    organizationId: string,
    employeeId: string,
    filename: string,
    contentType: string,
  ): Promise<PresignedUploadResult> {
    return this.s3.generatePresignedPutUrl({
      folder: `${HR_DOCUMENTS_SUBDIR}/${organizationId}/${employeeId}`,
      filename,
      contentType,
    });
  }

  presignUploadForInserviceDocument(
    organizationId: string,
    inserviceId: string,
    filename: string,
    contentType: string,
  ): Promise<PresignedUploadResult> {
    return this.s3.generatePresignedPutUrl({
      folder: `${INSERVICE_DOCUMENTS_SUBDIR}/${organizationId}/${inserviceId}`,
      filename,
      contentType,
    });
  }

  verifyUploaded(key: string): Promise<boolean> {
    return this.s3.objectExists(key);
  }

  async deleteInserviceDocument(relativePath: string): Promise<void> {
    if (!relativePath) return;
    if (this.storageConfig.isS3) {
      const bucket = this.storageConfig.s3Bucket;
      if (!bucket) return;
      const client = new S3Client({
        region: this.storageConfig.s3Region,
        credentials:
          this.storageConfig.s3AccessKeyId && this.storageConfig.s3SecretAccessKey
            ? {
                accessKeyId: this.storageConfig.s3AccessKeyId,
                secretAccessKey: this.storageConfig.s3SecretAccessKey,
              }
            : undefined,
      });
      try {
        await client.send(new DeleteObjectCommand({ Bucket: bucket, Key: relativePath }));
      } catch {
        /* swallow — storage cleanup is best-effort */
      }
      return;
    }
    const fullPath = this.getLocalFilePath(relativePath);
    if (fullPath) {
      try {
        fs.unlinkSync(fullPath);
      } catch {
        /* swallow — storage cleanup is best-effort */
      }
    }
  }

  /**
   * Resolve full path to a locally stored file. Returns null if S3 or file missing.
   */
  getLocalFilePath(relativePath: string): string | null {
    if (this.storageConfig.isS3) return null;
    const safe = path.normalize(relativePath).replace(/^(\.\.(\/|\\))+/, '');
    const fullPath = path.join(this.storageConfig.path, safe);
    return fs.existsSync(fullPath) ? fullPath : null;
  }

  delete(key: string): Promise<boolean> {
    return this.s3.deleteObject(key);
  }
}
