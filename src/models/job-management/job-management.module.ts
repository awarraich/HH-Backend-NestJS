import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JobPosting } from './entities/job-posting.entity';
import { JobApplication } from './entities/job-application.entity';
import { JobApplicationFieldValue } from './entities/job-application-field-value.entity';
import { OfferLetterAssignment } from './entities/offer-letter-assignment.entity';
import { OfferLetterAssignmentRole } from './entities/offer-letter-assignment-role.entity';
import { OfferLetterFieldValue } from './entities/offer-letter-field-value.entity';
import { CompetencyTemplate } from '../organizations/document-workflow/entities/competency-template.entity';
import { DocumentWorkflowRole } from '../organizations/document-workflow/entities/document-workflow-role.entity';
import { Organization } from '../organizations/entities/organization.entity';
import { Employee } from '../employees/entities/employee.entity';
import { EmployeeProfile } from '../employees/entities/employee-profile.entity';
import { User } from '../../authentication/entities/user.entity';
import { OrganizationStaff } from '../organizations/staff-management/entities/organization-staff.entity';
import { StaffRole } from '../organizations/staff-management/entities/staff-role.entity';
import { EmployeeDocument } from '../organizations/hr-files-setup/entities/employee-document.entity';
import { HrDocumentType } from '../organizations/hr-files-setup/entities/hr-document-type.entity';
import { JobManagementController } from './controllers/job-management.controller';
import { JobApplicationsController } from './controllers/job-applications.controller';
import { ApplicantJobManagementController } from './controllers/applicant-job-management.controller';
import { CareersController } from './controllers/careers.controller';
import {
  OfferLetterAssignmentController,
  EmployeeOfferLetterAssignmentsController,
} from './controllers/offer-letter-assignment.controller';
import { OfferLetterMyAssignmentsController } from './controllers/offer-letter-my-assignments.controller';
import { OfferLetterFillController } from './controllers/offer-letter-fill.controller';
import { JobManagementService } from './services/job-management.service';
import { JobApplicationDocumentStorageService } from './services/job-application-document-storage.service';
import { OfferLetterAssignmentService } from './services/offer-letter-assignment.service';
import { OfferLetterArchiveService } from './services/offer-letter-archive.service';
import { OrganizationsModule } from '../organizations/organizations.module';
import { StorageConfigModule } from '../../config/storage/config.module';
import { EmailModule } from '../../common/services/email/email.module';
import { MeetingIntegrationModule } from '../../common/services/meeting-integration/meeting-integration.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([
      JobPosting,
      JobApplication,
      JobApplicationFieldValue,
      Organization,
      Employee,
      EmployeeProfile,
      User,
      OfferLetterAssignment,
      OfferLetterAssignmentRole,
      OfferLetterFieldValue,
      CompetencyTemplate,
      DocumentWorkflowRole,
      OrganizationStaff,
      StaffRole,
      EmployeeDocument,
      HrDocumentType,
    ]),
    OrganizationsModule,
    StorageConfigModule,
    EmailModule,
    MeetingIntegrationModule,
  ],
  controllers: [
    JobManagementController,
    JobApplicationsController,
    ApplicantJobManagementController,
    CareersController,
    OfferLetterAssignmentController,
    EmployeeOfferLetterAssignmentsController,
    OfferLetterMyAssignmentsController,
    OfferLetterFillController,
  ],
  providers: [
    JobManagementService,
    JobApplicationDocumentStorageService,
    OfferLetterAssignmentService,
    OfferLetterArchiveService,
  ],
  exports: [JobManagementService, OfferLetterAssignmentService],
})
export class JobManagementModule {}
