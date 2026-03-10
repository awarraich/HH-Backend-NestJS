import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JobPosting } from './entities/job-posting.entity';
import { JobApplication } from './entities/job-application.entity';
import { JobManagementController } from './job-management.controller';
import { JobApplicationsController } from './job-applications.controller';
import { CareersController } from './careers.controller';
import { JobManagementService } from './job-management.service';
import { OrganizationsModule } from '../organizations/organizations.module';

@Module({
  imports: [TypeOrmModule.forFeature([JobPosting, JobApplication]), OrganizationsModule],
  controllers: [JobManagementController, JobApplicationsController, CareersController],
  providers: [JobManagementService],
  exports: [JobManagementService],
})
export class JobManagementModule {}
