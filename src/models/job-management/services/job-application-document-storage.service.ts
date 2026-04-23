import { Injectable } from '@nestjs/common';
import { S3Service, PresignedUploadResult } from '../../../common/services/s3/s3.service';

const JOB_APPLICATION_DOCUMENTS_SUBDIR = 'job-application-documents';

@Injectable()
export class JobApplicationDocumentStorageService {
  constructor(private readonly s3: S3Service) {}

  presignUpload(filename: string, contentType: string): Promise<PresignedUploadResult> {
    return this.s3.generatePresignedPutUrl({
      folder: JOB_APPLICATION_DOCUMENTS_SUBDIR,
      filename,
      contentType,
    });
  }

  verifyUploaded(key: string): Promise<boolean> {
    return this.s3.objectExists(key);
  }

  getPresignedViewUrl(key: string, expiresIn?: number): Promise<string> {
    return this.s3.generatePresignedGetUrl(key, expiresIn);
  }

  delete(key: string): Promise<boolean> {
    return this.s3.deleteObject(key);
  }
}
