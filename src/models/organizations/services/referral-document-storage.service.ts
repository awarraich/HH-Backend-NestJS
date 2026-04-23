import { Injectable } from '@nestjs/common';
import { S3Service, PresignedUploadResult } from '../../../common/services/s3/s3.service';

const REFERRAL_DOCUMENTS_SUBDIR = 'referral-documents';

@Injectable()
export class ReferralDocumentStorageService {
  constructor(private readonly s3: S3Service) {}

  presignUpload(filename: string, contentType: string): Promise<PresignedUploadResult> {
    return this.s3.generatePresignedPutUrl({
      folder: REFERRAL_DOCUMENTS_SUBDIR,
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
