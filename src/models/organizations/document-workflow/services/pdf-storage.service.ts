import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as fs from 'fs';
import * as path from 'path';
import { randomUUID } from 'crypto';
import { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } from '@aws-sdk/client-s3';
import { StorageConfigService } from '../../../../config/storage/config.service';

const DOCUMENT_WORKFLOW_SUBDIR = 'document-workflow';

@Injectable()
export class PdfStorageService {
  constructor(
    private readonly storageConfig: StorageConfigService,
    private readonly configService: ConfigService,
  ) {}

  async upload(
    buffer: Buffer,
    originalFilename: string,
    organizationId: string,
    templateId: string,
  ): Promise<{ file_key: string; original_name: string; size_bytes: number }> {
    const ext = path.extname(originalFilename) || '.pdf';
    const storedName = `${Date.now()}_${randomUUID()}${ext}`;
    const relativePath = `${DOCUMENT_WORKFLOW_SUBDIR}/${organizationId}/${templateId}/${storedName}`;

    if (this.storageConfig.isS3) {
      await this.saveToS3(buffer, relativePath, originalFilename);
    } else {
      await this.saveToLocal(buffer, relativePath);
    }

    return {
      file_key: relativePath,
      original_name: originalFilename,
      size_bytes: buffer.length,
    };
  }

  async getPresignedUrl(key: string): Promise<string> {
    if (this.storageConfig.isS3) {
      const bucket = this.storageConfig.s3Bucket;
      const region = this.storageConfig.s3Region;
      return `https://${bucket}.s3.${region}.amazonaws.com/${key}`;
    }

    return path.join(this.storageConfig.path, key);
  }

  async delete(key: string): Promise<void> {
    if (this.storageConfig.isS3) {
      const client = this.createS3Client();
      await client.send(
        new DeleteObjectCommand({ Bucket: this.storageConfig.s3Bucket, Key: key }),
      );
      return;
    }

    const fullPath = path.join(this.storageConfig.path, key);
    if (fs.existsSync(fullPath)) {
      fs.unlinkSync(fullPath);
    }
  }

  async getFileStream(
    key: string,
    fileName: string,
  ): Promise<{ stream: NodeJS.ReadableStream; contentType: string }> {
    if (this.storageConfig.isS3) {
      const client = this.createS3Client();
      const response = await client.send(
        new GetObjectCommand({ Bucket: this.storageConfig.s3Bucket, Key: key }),
      );
      if (!response.Body) throw new Error('File not found in storage');
      const contentType = response.ContentType ?? this.guessContentType(fileName);
      return { stream: response.Body as NodeJS.ReadableStream, contentType };
    }

    const fullPath = path.join(this.storageConfig.path, key);
    if (!fs.existsSync(fullPath)) throw new Error('File not found in storage');
    const stream = fs.createReadStream(fullPath);
    const contentType = this.guessContentType(fileName);
    return { stream, contentType };
  }

  private createS3Client(): S3Client {
    return new S3Client({
      region: this.storageConfig.s3Region,
      credentials:
        this.storageConfig.s3AccessKeyId && this.storageConfig.s3SecretAccessKey
          ? {
              accessKeyId: this.storageConfig.s3AccessKeyId,
              secretAccessKey: this.storageConfig.s3SecretAccessKey,
            }
          : undefined,
    });
  }

  private async saveToS3(buffer: Buffer, key: string, originalFilename: string): Promise<void> {
    const bucket = this.storageConfig.s3Bucket;
    if (!bucket) throw new Error('S3 bucket not configured (STORAGE_TYPE=s3 requires S3_BUCKET_NAME)');

    const client = this.createS3Client();
    await client.send(
      new PutObjectCommand({
        Bucket: bucket,
        Key: key,
        Body: buffer,
        ContentType: this.guessContentType(originalFilename),
      }),
    );
  }

  private async saveToLocal(buffer: Buffer, relativePath: string): Promise<void> {
    const fullPath = path.join(this.storageConfig.path, relativePath);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });
    fs.writeFileSync(fullPath, buffer);
  }

  private guessContentType(filename: string): string {
    const ext = path.extname(filename).toLowerCase();
    const map: Record<string, string> = {
      '.pdf': 'application/pdf',
      '.png': 'image/png',
      '.jpg': 'image/jpeg',
      '.jpeg': 'image/jpeg',
    };
    return map[ext] ?? 'application/octet-stream';
  }
}
