import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as fs from 'fs';
import * as path from 'path';
import { randomUUID } from 'crypto';
import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';
import { StorageConfigService } from '../../../../config/storage/config.service';

const COMPLIANCE_DOCUMENTS_SUBDIR = 'compliance-documents';

@Injectable()
export class OrganizationDocumentStorageService {
  constructor(
    private readonly storageConfig: StorageConfigService,
    private readonly configService: ConfigService,
  ) {}

  async saveDocument(
    buffer: Buffer,
    originalFilename: string,
    organizationId: string,
  ): Promise<{ file_name: string; file_path: string }> {
    const sanitized = this.sanitizeFilename(originalFilename);
    const ext = path.extname(sanitized) || '';
    const storedName = `${randomUUID()}${ext}`;
    const relativePath = `${COMPLIANCE_DOCUMENTS_SUBDIR}/${organizationId}/${storedName}`;

    if (this.storageConfig.isS3) {
      await this.saveToS3(buffer, relativePath, originalFilename);
      return { file_name: originalFilename, file_path: relativePath };
    }
    return this.saveToLocal(buffer, relativePath, originalFilename);
  }

  async getFileStream(
    relativePath: string,
    fileName: string,
  ): Promise<{ stream: NodeJS.ReadableStream; contentType: string }> {
    if (this.storageConfig.isS3) {
      const bucket = this.storageConfig.s3Bucket;
      if (!bucket) throw new Error('S3 bucket not configured');

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

      const response = await client.send(
        new GetObjectCommand({ Bucket: bucket, Key: relativePath }),
      );
      if (!response.Body) throw new Error('File not found in storage');

      const contentType = response.ContentType ?? this.guessContentType(fileName);
      return { stream: response.Body as NodeJS.ReadableStream, contentType };
    }

    const fullPath = this.getLocalFilePath(relativePath);
    if (!fullPath) throw new Error('File not found in storage');

    const stream = fs.createReadStream(fullPath);
    const contentType = this.guessContentType(fileName);
    return { stream, contentType };
  }

  getLocalFilePath(relativePath: string): string | null {
    if (this.storageConfig.isS3) return null;
    const safe = path.normalize(relativePath).replace(/^(\.\.(\/|\\))+/, '');
    const fullPath = path.join(this.storageConfig.path, safe);
    return fs.existsSync(fullPath) ? fullPath : null;
  }

  private sanitizeFilename(name: string): string {
    return path.basename(name).replace(/[^a-zA-Z0-9._-]/g, '_') || 'document';
  }

  private saveToLocal(
    buffer: Buffer,
    relativePath: string,
    originalFilename: string,
  ): Promise<{ file_name: string; file_path: string }> {
    const fullPath = path.join(this.storageConfig.path, relativePath);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });
    fs.writeFileSync(fullPath, buffer);
    return Promise.resolve({ file_name: originalFilename, file_path: relativePath });
  }

  private async saveToS3(buffer: Buffer, key: string, originalFilename: string): Promise<void> {
    const bucket = this.storageConfig.s3Bucket;
    if (!bucket) throw new Error('S3 bucket not configured (STORAGE_TYPE=s3 requires S3_BUCKET_NAME)');

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

    await client.send(
      new PutObjectCommand({
        Bucket: bucket,
        Key: key,
        Body: buffer,
        ContentType: this.guessContentType(originalFilename),
      }),
    );
  }

  private guessContentType(filename: string): string {
    const ext = path.extname(filename).toLowerCase();
    const map: Record<string, string> = {
      '.pdf': 'application/pdf',
      '.doc': 'application/msword',
      '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      '.jpg': 'image/jpeg',
      '.jpeg': 'image/jpeg',
      '.png': 'image/png',
      '.gif': 'image/gif',
      '.txt': 'text/plain',
    };
    return map[ext] ?? 'application/octet-stream';
  }
}
