import { Global, Module } from '@nestjs/common';
import { S3Service } from './s3.service';
import { StorageConfigModule } from '../../../config/storage/config.module';

@Global()
@Module({
  imports: [StorageConfigModule],
  providers: [S3Service],
  exports: [S3Service],
})
export class S3Module {}
