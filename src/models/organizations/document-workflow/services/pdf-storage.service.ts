import { Injectable } from '@nestjs/common';
import * as path from 'path';
import { randomUUID } from 'crypto';
import { S3Service, PresignedUploadResult } from '../../../../common/services/s3/s3.service';

const DOCUMENT_WORKFLOW_SUBDIR = 'document-workflow';

@Injectable()
export class PdfStorageService {
  constructor(private readonly s3: S3Service) {}

  async upload(
    buffer: Buffer,
    originalFilename: string,
    organizationId: string,
    templateId: string,
  ): Promise<{ file_key: string; original_name: string; size_bytes: number }> {
    const ext = path.extname(originalFilename) || '.pdf';
    const key = `${DOCUMENT_WORKFLOW_SUBDIR}/${organizationId}/${templateId}/${Date.now()}_${randomUUID()}${ext}`;

    await this.s3.putObject({
      key,
      body: buffer,
      contentType: this.guessContentType(originalFilename),
    });

    return {
      file_key: key,
      original_name: originalFilename,
      size_bytes: buffer.length,
    };
  }

  presignUpload(
    organizationId: string,
    templateId: string,
    filename: string,
    contentType: string,
  ): Promise<PresignedUploadResult> {
    return this.s3.generatePresignedPutUrl({
      folder: `${DOCUMENT_WORKFLOW_SUBDIR}/${organizationId}/${templateId}`,
      filename,
      contentType,
    });
  }

  verifyUploaded(key: string): Promise<boolean> {
    return this.s3.objectExists(key);
  }

  getPresignedUrl(key: string, expiresIn?: number): Promise<string> {
    return this.s3.generatePresignedGetUrl(key, expiresIn);
  }

  delete(key: string): Promise<boolean> {
    return this.s3.deleteObject(key);
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
