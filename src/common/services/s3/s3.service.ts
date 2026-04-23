import { Injectable, InternalServerErrorException, Logger, OnModuleInit } from '@nestjs/common';
import {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
  HeadObjectCommand,
} from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { randomUUID } from 'crypto';
import * as path from 'path';
import { StorageConfigService } from '../../../config/storage/config.service';

export interface PresignedUploadResult {
  uploadUrl: string;
  key: string;
  expiresIn: number;
}

export interface BuildKeyOptions {
  folder: string;
  filename: string;
}

const DEFAULT_PUT_EXPIRES_IN = 300;
const DEFAULT_GET_EXPIRES_IN = 300;

@Injectable()
export class S3Service implements OnModuleInit {
  private readonly logger = new Logger(S3Service.name);
  private client!: S3Client;
  private bucket!: string;

  constructor(private readonly storageConfig: StorageConfigService) {}

  onModuleInit(): void {
    this.bucket = this.storageConfig.s3Bucket;
    if (!this.bucket) {
      throw new Error('S3_BUCKET_NAME is required but not set.');
    }

    this.client = new S3Client({
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

  buildKey({ folder, filename }: BuildKeyOptions): string {
    const safeName = path.basename(filename).replace(/[^a-zA-Z0-9._-]/g, '_');
    const ext = path.extname(safeName);
    const cleanFolder = folder.replace(/^\/+|\/+$/g, '');
    return ext ? `${cleanFolder}/${randomUUID()}${ext}` : `${cleanFolder}/${randomUUID()}`;
  }

  async generatePresignedPutUrl(params: {
    folder: string;
    filename: string;
    contentType: string;
    expiresIn?: number;
  }): Promise<PresignedUploadResult> {
    const key = this.buildKey({ folder: params.folder, filename: params.filename });
    const expiresIn = params.expiresIn ?? DEFAULT_PUT_EXPIRES_IN;

    const command = new PutObjectCommand({
      Bucket: this.bucket,
      Key: key,
      ContentType: params.contentType,
    });

    const uploadUrl = await getSignedUrl(this.client, command, { expiresIn });
    return { uploadUrl, key, expiresIn };
  }

  async generatePresignedGetUrl(key: string, expiresIn: number = DEFAULT_GET_EXPIRES_IN): Promise<string> {
    const command = new GetObjectCommand({ Bucket: this.bucket, Key: key });
    return getSignedUrl(this.client, command, { expiresIn });
  }

  async objectExists(key: string): Promise<boolean> {
    try {
      await this.client.send(new HeadObjectCommand({ Bucket: this.bucket, Key: key }));
      return true;
    } catch {
      return false;
    }
  }

  async deleteObject(key: string): Promise<boolean> {
    try {
      await this.client.send(new DeleteObjectCommand({ Bucket: this.bucket, Key: key }));
      return true;
    } catch (err) {
      this.logger.error(`Failed to delete S3 object ${key}`, err instanceof Error ? err.stack : undefined);
      return false;
    }
  }

  async getObjectAsBuffer(key: string): Promise<Buffer> {
    const response = await this.client.send(new GetObjectCommand({ Bucket: this.bucket, Key: key }));
    if (!response.Body) {
      throw new InternalServerErrorException(`S3 object ${key} has no body`);
    }
    const stream = response.Body as NodeJS.ReadableStream;
    const chunks: Buffer[] = [];
    return new Promise<Buffer>((resolve, reject) => {
      stream.on('data', (chunk: Buffer | string) => {
        chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
      });
      stream.on('end', () => resolve(Buffer.concat(chunks)));
      stream.on('error', reject);
    });
  }

  async putObject(params: {
    key: string;
    body: Buffer;
    contentType: string;
  }): Promise<void> {
    try {
      await this.client.send(
        new PutObjectCommand({
          Bucket: this.bucket,
          Key: params.key,
          Body: params.body,
          ContentType: params.contentType,
        }),
      );
    } catch (err) {
      this.logger.error(
        `Failed to put S3 object ${params.key}`,
        err instanceof Error ? err.stack : undefined,
      );
      throw new InternalServerErrorException('Failed to store file');
    }
  }
}
