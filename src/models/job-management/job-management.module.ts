import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JobPosting } from './entities/job-posting.entity';
import { JobApplication } from './entities/job-application.entity';
import { Organization } from '../organizations/entities/organization.entity';
import { Employee } from '../employees/entities/employee.entity';
import { JobManagementController } from './controllers/job-management.controller';
import { JobApplicationsController } from './controllers/job-applications.controller';
import { CareersController } from './controllers/careers.controller';
import { JobManagementService } from './services/job-management.service';
import { JobApplicationDocumentStorageService } from './services/job-application-document-storage.service';
import { OrganizationsModule } from '../organizations/organizations.module';
import { StorageConfigModule } from '../../config/storage/config.module';
import { EmailModule } from '../../common/services/email/email.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([JobPosting, JobApplication, Organization, Employee]),
    OrganizationsModule,
    StorageConfigModule,
    EmailModule,
  ],
  controllers: [JobManagementController, JobApplicationsController, CareersController],
  providers: [JobManagementService, JobApplicationDocumentStorageService],
  exports: [JobManagementService],
})
export class JobManagementModule {}
