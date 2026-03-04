import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JobPosting } from './entities/job-posting.entity';
import { JobManagementController } from './job-management.controller';
import { JobManagementService } from './job-management.service';
import { OrganizationsModule } from '../organizations/organizations.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([JobPosting]),
    OrganizationsModule,
  ],
  controllers: [JobManagementController],
  providers: [JobManagementService],
  exports: [JobManagementService],
})
export class JobManagementModule {}
