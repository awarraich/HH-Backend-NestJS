import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JobPosting } from './entities/job-posting.entity';
import { JobApplication } from './entities/job-application.entity';
import { OfferLetterSigningToken } from './entities/offer-letter-signing-token.entity';
import { Organization } from '../organizations/entities/organization.entity';
import { Employee } from '../employees/entities/employee.entity';
import { User } from '../../authentication/entities/user.entity';
import { JobManagementController } from './controllers/job-management.controller';
import { JobApplicationsController } from './controllers/job-applications.controller';
import { CareersController } from './controllers/careers.controller';
import { OfferLetterSigningController } from './controllers/offer-letter-signing.controller';
import { JobManagementService } from './services/job-management.service';
import { JobApplicationDocumentStorageService } from './services/job-application-document-storage.service';
import { OfferLetterSigningService } from './services/offer-letter-signing.service';
import { OrganizationsModule } from '../organizations/organizations.module';
import { StorageConfigModule } from '../../config/storage/config.module';
import { EmailModule } from '../../common/services/email/email.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([JobPosting, JobApplication, Organization, Employee, OfferLetterSigningToken, User]),
    OrganizationsModule,
    StorageConfigModule,
    EmailModule,
  ],
  controllers: [
    JobManagementController,
    JobApplicationsController,
    CareersController,
    OfferLetterSigningController,
  ],
  providers: [
    JobManagementService,
    JobApplicationDocumentStorageService,
    OfferLetterSigningService,
  ],
  exports: [JobManagementService],
})
export class JobManagementModule {}
