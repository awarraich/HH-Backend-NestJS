import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as fs from 'fs';
import * as path from 'path';
import { randomUUID } from 'crypto';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import { StorageConfigService } from '../../../config/storage/config.service';

const BLOG_IMAGES_SUBDIR = 'blog-images';

@Injectable()
export class BlogImageStorageService {
  constructor(
    private readonly storageConfig: StorageConfigService,
    private readonly configService: ConfigService,
  ) {}

  /**
   * Save a blog image to local disk or S3. Returns file_name (original) and file_url.
   */
  async saveBlogImage(
    buffer: Buffer,
    originalFilename: string,
  ): Promise<{ file_name: string; file_url: string }> {
    const sanitized = this.sanitizeFilename(originalFilename);
    const ext = path.extname(sanitized) || '.jpg';
    const storedName = `${randomUUID()}${ext}`;

    if (this.storageConfig.isS3) {
      return this.saveToS3(buffer, storedName, originalFilename);
    }
    return this.saveToLocal(buffer, storedName, originalFilename);
  }

  private sanitizeFilename(name: string): string {
    const base = path.basename(name).replace(/[^a-zA-Z0-9._-]/g, '_');
    return base || 'image';
  }

  private async saveToLocal(
    buffer: Buffer,
    storedName: string,
    originalFilename: string,
  ): Promise<{ file_name: string; file_url: string }> {
    const dir = path.join(this.storageConfig.path, BLOG_IMAGES_SUBDIR);
    fs.mkdirSync(dir, { recursive: true });
    const filePath = path.join(dir, storedName);
    fs.writeFileSync(filePath, buffer);

    const baseUrl =
      this.configService.get<string>('APP_PUBLIC_URL') ||
      this.configService.get<string>('HHBACKEND_URL') ||
      'http://localhost:3000';
    const apiPrefix = this.configService.get<string>('API_PREFIX', 'v1/api');
    const fileUrl = `${baseUrl.replace(/\/$/, '')}/${apiPrefix}/blogs/images/${storedName}`;

    return { file_name: originalFilename, file_url: fileUrl };
  }

  private async saveToS3(
    buffer: Buffer,
    storedName: string,
    originalFilename: string,
  ): Promise<{ file_name: string; file_url: string }> {
    const bucket = this.storageConfig.s3Bucket;
    const region = this.storageConfig.s3Region;
    if (!bucket) {
      throw new Error('S3 bucket not configured (STORAGE_TYPE=s3 requires S3_BUCKET_NAME)');
    }

    const client = new S3Client({
      region,
      credentials:
        this.storageConfig.s3AccessKeyId && this.storageConfig.s3SecretAccessKey
          ? {
              accessKeyId: this.storageConfig.s3AccessKeyId,
              secretAccessKey: this.storageConfig.s3SecretAccessKey,
            }
          : undefined,
    });

    const key = `${BLOG_IMAGES_SUBDIR}/${storedName}`;
    await client.send(
      new PutObjectCommand({
        Bucket: bucket,
        Key: key,
        Body: buffer,
        ContentType: this.guessContentType(originalFilename),
      }),
    );

    const fileUrl = `https://${bucket}.s3.${region}.amazonaws.com/${key}`;
    return { file_name: originalFilename, file_url: fileUrl };
  }

  private guessContentType(filename: string): string {
    const ext = path.extname(filename).toLowerCase();
    const map: Record<string, string> = {
      '.jpg': 'image/jpeg',
      '.jpeg': 'image/jpeg',
      '.png': 'image/png',
      '.gif': 'image/gif',
      '.webp': 'image/webp',
      '.svg': 'image/svg+xml',
    };
    return map[ext] ?? 'image/jpeg';
  }

  /**
   * Resolve path to a locally stored file by stored filename (for serving). Returns null if not local or file missing.
   */
  getLocalFilePath(storedFilename: string): string | null {
    if (this.storageConfig.isS3) return null;
    const safe = path.basename(storedFilename).replace(/[^a-zA-Z0-9._-]/g, '');
    if (!safe || safe !== storedFilename) return null;
    const filePath = path.join(this.storageConfig.path, BLOG_IMAGES_SUBDIR, storedFilename);
    return fs.existsSync(filePath) ? filePath : null;
  }
}
