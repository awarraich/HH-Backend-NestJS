import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { StorageConfigModule } from '../../config/storage/config.module';
import { Organization } from './entities/organization.entity';
import { OrganizationType } from './entities/organization-type.entity';
import { OrganizationTypeAssignment } from './entities/organization-type-assignment.entity';
import { OrganizationProfile } from './entities/organization-profile.entity';
import { OrganizationRolePermission } from './entities/organization-role-permission.entity';
import { Referral } from './entities/referral.entity';
import { ReferralOrganization } from './entities/referral-organization.entity';
import { ReferralMessage } from './entities/referral-message.entity';
import { ReferralDocument } from './entities/referral-document.entity';
import { ReferralLastRead } from './entities/referral-last-read.entity';
import { OrganizationFeature } from './entities/organization-feature.entity';
import { StaffRole } from './staff-management/entities/staff-role.entity';
import { OrganizationStaff } from './staff-management/entities/organization-staff.entity';
import { OrganizationStaffRolePermission } from './staff-management/entities/organization-staff-role-permission.entity';
import { Employee } from '../employees/entities/employee.entity';
import { User } from '../../authentication/entities/user.entity';
import { Patient } from '../patients/entities/patient.entity';
import { AuthenticationModule } from '../../authentication/auth.module';
import { EmailModule } from '../../common/services/email/email.module';
import { AuditLogModule } from '../../common/services/audit/audit-log.module';
import { OrganizationRoleGuard } from '../../common/guards/organization-role.guard';
import { PatientsModule } from '../patients/patients.module';
import { OrganizationsService } from './services/organizations.service';
import { OrganizationRoleService } from './services/organization-role.service';
import { OrganizationPermissionService } from './services/organization-permission.service';
import { ReferralsService } from './services/referrals.service';
import { ReferralMessagesService } from './services/referral-messages.service';
import { ReferralDocumentStorageService } from './services/referral-document-storage.service';
import { OrganizationsController } from './controllers/organizations.controller';
import { OrganizationFeaturesController } from './controllers/organization-features.controller';
import { OrganizationTypesController } from './controllers/organization-types.controller';
import { ReferralsController } from './controllers/referrals.controller';
import { ReferralOrganizationsController } from './controllers/referral-organizations.controller';
import { OrganizationStaffController } from './staff-management/controllers/organization-staff.controller';
import { OrganizationStaffService } from './staff-management/services/organization-staff.service';
import { HrDocumentType } from './hr-files-setup/entities/hr-document-type.entity';
import { HrDocumentTypeService } from './hr-files-setup/services/hr-document-type.service';
import { HrDocumentTypesController } from './hr-files-setup/controllers/hr-document-types.controller';
import { RequirementTag } from './hr-files-setup/entities/requirement-tag.entity';
import { RequirementDocumentType } from './hr-files-setup/entities/requirement-document-type.entity';
import { RequirementInserviceTraining } from './hr-files-setup/entities/requirement-inservice-training.entity';
import { InserviceTraining } from './hr-files-setup/entities/inservice-training.entity';
import { EmployeeRequirementTag } from './hr-files-setup/entities/employee-requirement-tag.entity';
import { RequirementTagService } from './hr-files-setup/services/requirement-tag.service';
import { EmployeeRequirementTagService } from './hr-files-setup/services/employee-requirement-tag.service';
import { RequirementTagsController } from './hr-files-setup/controllers/requirement-tags.controller';
import { EmployeeDocument } from './hr-files-setup/entities/employee-document.entity';
import { DocumentChunk } from './hr-files-setup/entities/document-chunk.entity';
import { EmployeeDocumentsService } from './hr-files-setup/services/employee-documents.service';
import { EmployeeDocumentsChatService } from './hr-files-setup/services/employee-documents-chat.service';
import { EmployeeDocumentStorageService } from './hr-files-setup/services/employee-document-storage.service';
import { EmployeeDocumentsController } from './hr-files-setup/controllers/employee-documents.controller';
import { EmployeeDocumentTypesController } from './hr-files-setup/controllers/employee-document-types.controller';
import { InserviceTrainingsController } from './hr-files-setup/controllers/inservice-trainings.controller';
import { InserviceQuizQuestionsController } from './hr-files-setup/controllers/inservice-quiz-questions.controller';
import { InserviceQuizQuestionsOrgController } from './hr-files-setup/controllers/inservice-quiz-questions-org.controller';
import { EmployeeDocumentTypeService } from './hr-files-setup/services/employee-document-type.service';
import { InserviceTrainingService } from './hr-files-setup/services/inservice-training.service';
import { InserviceQuizQuestionService } from './hr-files-setup/services/inservice-quiz-question.service';
import { InserviceQuizQuestion } from './hr-files-setup/entities/inservice-quiz-question.entity';
import { EmployeeDocumentAccessGuard } from '../../common/guards/employee-document-access.guard';
import { EmployeeDocumentTypeAccessGuard } from '../../common/guards/employee-document-type-access.guard';
import { EmbeddingModule } from '../../common/services/embedding/embedding.module';
import { OrganizationRepository } from './repositories/organization.repository';
import { ReferralRepository } from './repositories/referral.repository';
import { ReferralMessagesGateway } from './gateways/referral-messages.gateway';

@Module({
  imports: [
    ConfigModule,
    StorageConfigModule,
    TypeOrmModule.forFeature([
      Organization,
      OrganizationType,
      OrganizationTypeAssignment,
      OrganizationProfile,
      OrganizationRolePermission,
      OrganizationFeature,
      StaffRole,
      OrganizationStaff,
      OrganizationStaffRolePermission,
      HrDocumentType,
      RequirementTag,
      RequirementDocumentType,
      RequirementInserviceTraining,
      InserviceTraining,
      InserviceQuizQuestion,
      EmployeeRequirementTag,
      EmployeeDocument,
      DocumentChunk,
      Employee,
      User,
      Referral,
      ReferralOrganization,
      ReferralMessage,
      ReferralDocument,
      ReferralLastRead,
      Patient,
    ]),
    AuthenticationModule,
    EmailModule,
    AuditLogModule,
    PatientsModule,
    EmbeddingModule,
  ],
  controllers: [
    OrganizationsController,
    OrganizationFeaturesController,
    OrganizationTypesController,
    ReferralsController,
    ReferralOrganizationsController,
    OrganizationStaffController,
    HrDocumentTypesController,
    RequirementTagsController,
    EmployeeDocumentsController,
    EmployeeDocumentTypesController,
    InserviceTrainingsController,
    InserviceQuizQuestionsController,
    InserviceQuizQuestionsOrgController,
  ],
  providers: [
    OrganizationsService,
    OrganizationRoleService,
    OrganizationPermissionService,
    ReferralsService,
    ReferralMessagesService,
    ReferralDocumentStorageService,
    OrganizationStaffService,
    HrDocumentTypeService,
    EmployeeDocumentTypeService,
    InserviceTrainingService,
    InserviceQuizQuestionService,
    RequirementTagService,
    EmployeeRequirementTagService,
    EmployeeDocumentsService,
    EmployeeDocumentsChatService,
    EmployeeDocumentStorageService,
    EmployeeDocumentAccessGuard,
    EmployeeDocumentTypeAccessGuard,
    OrganizationRepository,
    ReferralRepository,
    OrganizationRoleGuard,
    ReferralMessagesGateway,
  ],
  exports: [
    TypeOrmModule,
    OrganizationsService,
    OrganizationRoleService,
    OrganizationStaffService,
    OrganizationRepository,
    ReferralsService,
    OrganizationRoleGuard,
    EmployeeDocumentsService,
    EmployeeRequirementTagService,
  ],
})
export class OrganizationsModule {}
