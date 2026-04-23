import { Injectable } from '@nestjs/common';
import { S3Service, PresignedUploadResult } from '../../../../common/services/s3/s3.service';

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

  getPresignedViewUrl(key: string, expiresIn?: number): Promise<string> {
    return this.s3.generatePresignedGetUrl(key, expiresIn);
  }

  async deleteInserviceDocument(key: string): Promise<void> {
    if (!key) return;
    await this.s3.deleteObject(key);
  }

  delete(key: string): Promise<boolean> {
    return this.s3.deleteObject(key);
  }
}
