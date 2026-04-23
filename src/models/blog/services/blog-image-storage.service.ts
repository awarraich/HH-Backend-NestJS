import { Injectable } from '@nestjs/common';
import { S3Service, PresignedUploadResult } from '../../../common/services/s3/s3.service';

const BLOG_IMAGES_SUBDIR = 'blog-images';
const BLOG_VIDEOS_SUBDIR = 'blog-videos';

@Injectable()
export class BlogImageStorageService {
  constructor(private readonly s3: S3Service) {}

  presignImageUpload(filename: string, contentType: string): Promise<PresignedUploadResult> {
    return this.s3.generatePresignedPutUrl({
      folder: BLOG_IMAGES_SUBDIR,
      filename,
      contentType,
    });
  }

  presignVideoUpload(filename: string, contentType: string): Promise<PresignedUploadResult> {
    return this.s3.generatePresignedPutUrl({
      folder: BLOG_VIDEOS_SUBDIR,
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
