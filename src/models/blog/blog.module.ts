import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { BlogController } from './controllers/blog.controller';
import { BlogService } from './services/blog.service';
import { BlogImageStorageService } from './services/blog-image-storage.service';
import { Blog } from './entities/blog.entity';
import { User } from '../../authentication/entities/user.entity';
import { StorageConfigModule } from '../../config/storage/config.module';

@Module({
  imports: [TypeOrmModule.forFeature([Blog, User]), StorageConfigModule],
  controllers: [BlogController],
  providers: [BlogService, BlogImageStorageService],
  exports: [BlogService, BlogImageStorageService],
})
export class BlogModule {}
