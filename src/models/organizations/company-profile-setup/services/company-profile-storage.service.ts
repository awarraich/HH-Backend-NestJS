import { Injectable } from '@nestjs/common';
import { S3Service, PresignedUploadResult } from '../../../../common/services/s3/s3.service';

const COMPANY_PROFILE_SUBDIR = 'company-profile';

@Injectable()
export class CompanyProfileStorageService {
  constructor(private readonly s3: S3Service) {}

  presignGalleryUpload(
    organizationId: string,
    filename: string,
    contentType: string,
  ): Promise<PresignedUploadResult> {
    return this.s3.generatePresignedPutUrl({
      folder: `${COMPANY_PROFILE_SUBDIR}/${organizationId}/gallery`,
      filename,
      contentType,
    });
  }

  presignVideoUpload(
    organizationId: string,
    filename: string,
    contentType: string,
  ): Promise<PresignedUploadResult> {
    return this.s3.generatePresignedPutUrl({
      folder: `${COMPANY_PROFILE_SUBDIR}/${organizationId}/videos`,
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
