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
import { RequirementDocumentTemplate } from './hr-files-setup/entities/requirement-document-template.entity';
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
import { EmployeeInserviceController } from './hr-files-setup/controllers/employee-inservice.controller';
import { EmployeeDocumentTypeService } from './hr-files-setup/services/employee-document-type.service';
import { InserviceCompletionService } from './hr-files-setup/services/inservice-completion.service';
import { InserviceTrainingService } from './hr-files-setup/services/inservice-training.service';
import { InserviceQuizQuestionService } from './hr-files-setup/services/inservice-quiz-question.service';
import { InserviceQuizQuestion } from './hr-files-setup/entities/inservice-quiz-question.entity';
import { InserviceCompletion } from './hr-files-setup/entities/inservice-completion.entity';
import { InserviceQuizAttempt } from './hr-files-setup/entities/inservice-quiz-attempt.entity';
import { OrganizationCompanyProfile } from './company-profile-setup/entities/organization-company-profile.entity';
import { OrganizationCompanyProfileService } from './company-profile-setup/services/organization-company-profile.service';
import { CompanyProfileStorageService } from './company-profile-setup/services/company-profile-storage.service';
import { OrganizationCompanyProfileController } from './company-profile-setup/controllers/organization-company-profile.controller';
import { EmployeeDocumentAccessGuard } from '../../common/guards/employee-document-access.guard';
import { EmployeeDocumentTypeAccessGuard } from '../../common/guards/employee-document-type-access.guard';
import { EmbeddingModule } from '../../common/services/embedding/embedding.module';
import { OrganizationRepository } from './repositories/organization.repository';
import { ReferralRepository } from './repositories/referral.repository';
import { ReferralMessagesGateway } from './gateways/referral-messages.gateway';
import { Department } from './scheduling/entities/department.entity';
import { Station } from './scheduling/entities/station.entity';
import { Room } from './scheduling/entities/room.entity';
import { Bed } from './scheduling/entities/bed.entity';
import { Chair } from './scheduling/entities/chair.entity';
import { Shift } from './scheduling/entities/shift.entity';
import { EmployeeShift } from './scheduling/entities/employee-shift.entity';
import { DepartmentConfigOption } from './scheduling/entities/department-config-option.entity';
import { DepartmentService } from './scheduling/services/department.service';
import { StationService } from './scheduling/services/station.service';
import { RoomService } from './scheduling/services/room.service';
import { BedService } from './scheduling/services/bed.service';
import { ChairService } from './scheduling/services/chair.service';
import { ShiftService } from './scheduling/services/shift.service';
import { EmployeeShiftService } from './scheduling/services/employee-shift.service';
import { EmployeeAvailabilityService } from './scheduling/services/employee-availability.service';
import { DepartmentConfigOptionService } from './scheduling/services/department-config-option.service';
import { DepartmentsController } from './scheduling/controllers/departments.controller';
import { StationsController } from './scheduling/controllers/stations.controller';
import { RoomsController } from './scheduling/controllers/rooms.controller';
import { BedsController } from './scheduling/controllers/beds.controller';
import { ChairsController } from './scheduling/controllers/chairs.controller';
import { ShiftsController } from './scheduling/controllers/shifts.controller';
import { EmployeeShiftsController } from './scheduling/controllers/employee-shifts.controller';
import { DepartmentConfigOptionsController } from './scheduling/controllers/department-config-options.controller';
import { EmployeeShiftsByEmployeeController } from './scheduling/controllers/employee-shifts-by-employee.controller';
import { OrganizationDocumentCategory } from './compliance-documents/entities/organization-document-category.entity';
import { OrganizationDocument } from './compliance-documents/entities/organization-document.entity';
import { OrganizationDocumentChunk } from './compliance-documents/entities/organization-document-chunk.entity';
import { OrganizationDocumentCategoriesService } from './compliance-documents/services/organization-document-categories.service';
import { OrganizationDocumentsService } from './compliance-documents/services/organization-documents.service';
import { OrganizationDocumentStorageService } from './compliance-documents/services/organization-document-storage.service';
import { OrganizationDocumentsChatService } from './compliance-documents/services/organization-documents-chat.service';
import { OrganizationDocumentCategoriesController } from './compliance-documents/controllers/organization-document-categories.controller';
import { OrganizationDocumentsController } from './compliance-documents/controllers/organization-documents.controller';
import { CompetencyTemplate } from './document-workflow/entities/competency-template.entity';
import { CompetencyAssignment } from './document-workflow/entities/competency-assignment.entity';
import { DocumentFieldValue } from '../external-documents/entities/document-field-value.entity';
import { TemplatesController } from './document-workflow/controllers/templates.controller';
import { AssignmentsController } from './document-workflow/controllers/assignments.controller';
import { TemplatesService } from './document-workflow/services/templates.service';
import { AssignmentsService } from './document-workflow/services/assignments.service';
import { PdfStorageService } from './document-workflow/services/pdf-storage.service';
import { DocumentWorkflowRole } from './document-workflow/entities/document-workflow-role.entity';
import { DocumentTemplateUserAssignment } from './document-workflow/entities/document-template-user-assignment.entity';
import { WorkflowRolesService } from './document-workflow/services/workflow-roles.service';
import { TemplateAssignmentsService } from './document-workflow/services/template-assignments.service';
import { WorkflowRolesController } from './document-workflow/controllers/workflow-roles.controller';
import { FilledDocumentTemplatesController } from './document-workflow/controllers/filled-document-templates.controller';

@Module({
  imports: [
    ConfigModule,
    StorageConfigModule,
    TypeOrmModule.forFeature([
      Department,
      Station,
      Room,
      Bed,
      Chair,
      Shift,
      EmployeeShift,
      DepartmentConfigOption,
      Organization,
      OrganizationType,
      OrganizationTypeAssignment,
      OrganizationProfile,
      OrganizationRolePermission,
      OrganizationFeature,
      StaffRole,
      OrganizationStaff,
      OrganizationStaffRolePermission,
      Employee,
      HrDocumentType,
      RequirementTag,
      RequirementDocumentType,
      RequirementInserviceTraining,
      InserviceTraining,
      InserviceQuizQuestion,
      InserviceCompletion,
      InserviceQuizAttempt,
      EmployeeRequirementTag,
      RequirementDocumentTemplate,
      EmployeeDocument,
      DocumentChunk,
      OrganizationCompanyProfile,
      Employee,
      User,
      Referral,
      ReferralOrganization,
      ReferralMessage,
      ReferralDocument,
      ReferralLastRead,
      Patient,
      OrganizationDocumentCategory,
      OrganizationDocument,
      OrganizationDocumentChunk,
      CompetencyTemplate,
      CompetencyAssignment,
      DocumentFieldValue,
      DocumentWorkflowRole,
      DocumentTemplateUserAssignment,
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
    EmployeeInserviceController,
    OrganizationCompanyProfileController,
    DepartmentsController,
    DepartmentConfigOptionsController,
    StationsController,
    RoomsController,
    BedsController,
    ChairsController,
    ShiftsController,
    EmployeeShiftsController,
    EmployeeShiftsByEmployeeController,
    OrganizationDocumentCategoriesController,
    OrganizationDocumentsController,
    TemplatesController,
    AssignmentsController,
    WorkflowRolesController,
    FilledDocumentTemplatesController,
  ],
  providers: [
    DepartmentService,
    DepartmentConfigOptionService,
    StationService,
    RoomService,
    BedService,
    ChairService,
    ShiftService,
    EmployeeShiftService,
    EmployeeAvailabilityService,
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
    InserviceCompletionService,
    RequirementTagService,
    EmployeeRequirementTagService,
    EmployeeDocumentsService,
    EmployeeDocumentsChatService,
    EmployeeDocumentStorageService,
    EmployeeDocumentAccessGuard,
    EmployeeDocumentTypeAccessGuard,
    OrganizationCompanyProfileService,
    CompanyProfileStorageService,
    OrganizationRepository,
    ReferralRepository,
    OrganizationRoleGuard,
    ReferralMessagesGateway,
    OrganizationDocumentCategoriesService,
    OrganizationDocumentsService,
    OrganizationDocumentStorageService,
    OrganizationDocumentsChatService,
    TemplatesService,
    AssignmentsService,
    PdfStorageService,
    WorkflowRolesService,
    TemplateAssignmentsService,
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
    OrganizationDocumentsService,
    OrganizationDocumentsChatService,
    ShiftService,
    EmployeeShiftService,
    EmployeeAvailabilityService,
  ],
})
export class OrganizationsModule {}
