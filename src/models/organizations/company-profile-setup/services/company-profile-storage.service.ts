import {
  Injectable,
  NotFoundException,
  InternalServerErrorException,
  HttpException,
} from '@nestjs/common';
import * as fs from 'fs';
import * as path from 'path';
import { randomUUID } from 'crypto';
import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';
import { StorageConfigService } from '../../../../config/storage/config.service';

const COMPANY_PROFILE_SUBDIR = 'company-profile';

/**
 * Storage for company profile gallery images and marketing videos.
 * Uses the same config as the rest of the app (local disk or S3).
 */
@Injectable()
export class CompanyProfileStorageService {
  constructor(private readonly storageConfig: StorageConfigService) {}

  /**
   * Save a gallery image. Returns file_name (original) and file_path (relative or key).
   */
  async saveGalleryImage(
    buffer: Buffer,
    originalFilename: string,
    organizationId: string,
  ): Promise<{ file_name: string; file_path: string }> {
    try {
      const sanitized = this.sanitizeFilename(originalFilename);
      const ext = path.extname(sanitized) || '.jpg';
      const storedName = `${randomUUID()}${ext}`;
      const relativePath = `${COMPANY_PROFILE_SUBDIR}/${organizationId}/gallery/${storedName}`;
      if (this.storageConfig.isS3) {
        await this.saveToS3(buffer, relativePath, originalFilename);
        return { file_name: originalFilename, file_path: relativePath };
      }
      return this.saveToLocal(buffer, relativePath, originalFilename);
    } catch (error) {
      if (error instanceof HttpException) throw error;
      throw new InternalServerErrorException(
        'Failed to save gallery image. Please try again later.',
      );
    }
  }

  /**
   * Save a marketing video. Returns file_name and file_path (relative or key).
   */
  async saveVideo(
    buffer: Buffer,
    originalFilename: string,
    organizationId: string,
  ): Promise<{ file_name: string; file_path: string }> {
    try {
      const sanitized = this.sanitizeFilename(originalFilename);
      const ext = path.extname(sanitized) || '.mp4';
      const storedName = `${randomUUID()}${ext}`;
      const relativePath = `${COMPANY_PROFILE_SUBDIR}/${organizationId}/videos/${storedName}`;
      if (this.storageConfig.isS3) {
        await this.saveToS3(buffer, relativePath, originalFilename);
        return { file_name: originalFilename, file_path: relativePath };
      }
      return this.saveToLocal(buffer, relativePath, originalFilename);
    } catch (error) {
      if (error instanceof HttpException) throw error;
      throw new InternalServerErrorException('Failed to save video. Please try again later.');
    }
  }

  /**
   * Returns a read stream and content type for the file at the given path. Throws if not found.
   */
  async getFileStream(
    relativePath: string,
    fileName: string,
  ): Promise<{ stream: NodeJS.ReadableStream; contentType: string }> {
    if (this.storageConfig.isS3) {
      const bucket = this.storageConfig.s3Bucket;
      if (!bucket) {
        throw new InternalServerErrorException('S3 bucket not configured');
      }
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
        const response = await client.send(
          new GetObjectCommand({ Bucket: bucket, Key: relativePath }),
        );
        if (!response.Body) {
          throw new NotFoundException('File not found in storage');
        }
        const contentType = response.ContentType ?? this.guessContentType(fileName);
        return { stream: response.Body as NodeJS.ReadableStream, contentType };
      } catch (err: unknown) {
        if (err && typeof err === 'object' && 'name' in err && (err as { name: string }).name === 'NoSuchKey') {
          throw new NotFoundException('File not found in storage');
        }
        if (err instanceof HttpException) throw err;
        throw new InternalServerErrorException(
          'Failed to load file from storage. Please try again later.',
        );
      }
    }
    const fullPath = this.getLocalFilePath(relativePath);
    if (!fullPath) {
      throw new NotFoundException('File not found in storage');
    }
    try {
      const stream = fs.createReadStream(fullPath);
      const contentType = this.guessContentType(fileName);
      return { stream, contentType };
    } catch (err: unknown) {
      if (err instanceof HttpException) throw err;
      throw new NotFoundException('File not found in storage');
    }
  }

  private sanitizeFilename(name: string): string {
    const base = path.basename(name).replace(/[^a-zA-Z0-9._-]/g, '_');
    return base || 'file';
  }

  private saveToLocal(
    buffer: Buffer,
    relativePath: string,
    originalFilename: string,
  ): Promise<{ file_name: string; file_path: string }> {
    const fullPath = path.join(this.storageConfig.path, relativePath);
    const dir = path.dirname(fullPath);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(fullPath, buffer);
    return Promise.resolve({ file_name: originalFilename, file_path: relativePath });
  }

  private async saveToS3(buffer: Buffer, key: string, originalFilename: string): Promise<void> {
    const bucket = this.storageConfig.s3Bucket;
    if (!bucket) {
      throw new InternalServerErrorException(
        'S3 bucket not configured (STORAGE_TYPE=s3 requires S3_BUCKET_NAME)',
      );
    }
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

  private getLocalFilePath(relativePath: string): string | null {
    if (this.storageConfig.isS3) return null;
    const safe = path.normalize(relativePath).replace(/^(\.\.(\/|\\))+/, '');
    const fullPath = path.join(this.storageConfig.path, safe);
    return fs.existsSync(fullPath) ? fullPath : null;
  }

  private guessContentType(filename: string): string {
    const ext = path.extname(filename).toLowerCase();
    const map: Record<string, string> = {
      '.jpg': 'image/jpeg',
      '.jpeg': 'image/jpeg',
      '.png': 'image/png',
      '.gif': 'image/gif',
      '.webp': 'image/webp',
      '.mp4': 'video/mp4',
      '.webm': 'video/webm',
      '.mov': 'video/quicktime',
    };
    return map[ext] ?? 'application/octet-stream';
  }
}
