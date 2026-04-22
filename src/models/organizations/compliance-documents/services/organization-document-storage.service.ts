import { Injectable } from '@nestjs/common';
import { S3Service, PresignedUploadResult } from '../../../../common/services/s3/s3.service';

const COMPLIANCE_DOCUMENTS_SUBDIR = 'compliance-documents';

@Injectable()
export class OrganizationDocumentStorageService {
  constructor(private readonly s3: S3Service) {}

  presignUpload(
    organizationId: string,
    filename: string,
    contentType: string,
  ): Promise<PresignedUploadResult> {
    return this.s3.generatePresignedPutUrl({
      folder: `${COMPLIANCE_DOCUMENTS_SUBDIR}/${organizationId}`,
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
