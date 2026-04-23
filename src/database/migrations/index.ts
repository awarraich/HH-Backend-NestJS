import type { MigrationInterface } from 'typeorm';
import { CreateUsersTable20260101000000 } from './20260101000000-create-users-table.js';
import { AddGoogleIdToUsers20260128060000 } from './20260128060000-add-google-id-to-users.js';
import { CreateCreditPackagesTable20260129055907 } from './20260129055907-create-credit-packages-table.js';
import { AddPasswordChangedAtToUsers20260202040507 } from './20260202040507-add-password-changed-at-to-users.js';
import { AddTemporaryPasswordFields20260202052121 } from './20260202052121-add-temporary-password-fields.js';
import { CreateOrganizationsPatientsTables20260208000000 } from './20260208000000-create-organizations-patients-tables.js';
import { PatientsNullableUserIdAndOrganization20260209000001 } from './20260209000001-patients-nullable-user-id-and-organization.js';
import { CreateReferralTables20260209000002 } from './20260209000002-create-referral-tables.js';
import { BackfillReferralStatusAssigned20260210000001 } from './20260210000001-backfill-referral-status-assigned.js';
import { BackfillReferralStatusFromSelectedOrgResponse20260210000002 } from './20260210000002-backfill-referral-status-from-selected-org-response.js';
import { CreateReferralDocumentsTable20260210000003 } from './20260210000003-create-referral-documents-table.js';
import { RemoveReferralStatusAndAssignmentOutcome20260212000001 } from './20260212000001-remove-referral-status-and-assignment-outcome.js';
import { MakeUsersPasswordNullable20260217000001 } from './20260217000001-make-users-password-nullable.js';
import { CreatePatientMedicationsTables20260218000001 } from './20260218000001-create-patient-medications-tables.js';
import { AddRecordedByToMedicationAdministrations20260218000002 } from './20260218000002-add-recorded-by-to-medication-administrations.js';
import { AddDeletedAtPatientMedications20260218000003 } from './20260218000003-add-deleted-at-patient-medications.js';
import { BackfillUsersEmailNotNull20260219000001 } from './20260219000001-backfill-users-email-not-null.js';
import { CreateStaffManagementTables20260219000001 } from './20260219000001-create-staff-management-tables.js';
import { SeedRolesTable20260219100000 } from './20260219100000-seed-roles-table.js';
import { AddStaffSystemRole20260219100000 } from './20260219100000-add-staff-system-role.js';
import { SeedOrganizationTypesTable20260219100001 } from './20260219100001-seed-organization-types-table.js';
import { CreateOrganizationFeaturesTable20260219110000 } from './20260219110000-create-organization-features-table.js';
import { LinkStaffRolePermissionsToOrganizationFeatures20260219110001 } from './20260219110001-link-staff-role-permissions-to-organization-features.js';
import { AddMedicationEmbedding20260223100000 } from './20260223100000-add-medication-embedding.js';
import { CreateProviderRolesTable20260224100000 } from './20260224100000-create-provider-roles-table.js';
import { AlterEmployeesAndProfiles20260224100001 } from './20260224100001-alter-employees-and-profiles.js';
import { DropEmployeeRoleAndOnboardingStatus20260224100003 } from './20260224100003-drop-employee-role-and-onboarding-status.js';
import { CreateHrDocumentTypesTable20260226100000 } from './20260226100000-create-hr-document-types-table.js';
import { CreateEmployeeDocumentsTable20260227100000 } from './20260227100000-create-employee-documents-table.js';
import { CreateDocumentChunksAndVector20260227100001 } from './20260227100001-create-document-chunks-and-vector.js';
import { AddDeletedAtEmployeeDocuments20260227100002 } from './20260227100002-add-deleted-at-employee-documents.js';
import { PartialUniqueEmployeeDocuments20260227100003 } from './20260227100003-partial-unique-employee-documents.js';
import { CreatePatientChatTables20260302000000 } from './20260302000000-create-patient-chat-tables.js';
import { CreateRequirementTagsTables20260303110000 } from './20260303110000-create-requirement-tags-tables.js';
import { CreateEmployeeRequirementTagsTable20260303110001 } from './20260303110001-create-employee-requirement-tags-table.js';
import { CreateJobPostingsTable20260304000000 } from './20260304000000-create-job-postings-table.js';
import { AddEmployeeIdToHrDocumentTypes20260304100000 } from './20260304100000-add-employee-id-to-hr-document-types.js';
import { EmployeeDocumentTypesNoOrg20260305100000 } from './20260305100000-employee-document-types-no-org.js';
import { CreateInserviceTrainingsTable20260305120000 } from './20260305120000-create-inservice-trainings-table.js';
import { CreateRequirementInserviceTrainingsTable20260305120001 } from './20260305120001-create-requirement-inservice-trainings-table.js';
import { SeedGlobalHrDocumentTypes20260306100000 } from './20260306100000-seed-global-hr-document-types.js';
import { AddHasQuizAndPassingScoreToInserviceTrainings20260306120000 } from './20260306120000-add-has-quiz-and-passing-score-to-inservice-trainings.js';
import { CreateInserviceQuizQuestionsTable20260306120001 } from './20260306120001-create-inservice-quiz-questions-table.js';
import { CreateJobApplicationsTable20260307000000 } from './20260307000000-create-job-applications-table.js';
import { CreateInserviceCompletionsAndQuizAttempts20260311100000 } from './20260311100000-create-inservice-completions-and-quiz-attempts.js';
import { AddDisplayNameToUsers20260312000000 } from './20260312000000-add-display-name-to-users.js';
import { CreateBlogLikesAndComments20260312000001 } from './20260312000001-create-blog-likes-and-comments.js';
import { AddGuestSupportToBlogLikesComments20260313000000 } from './20260313000000-add-guest-support-to-blog-likes-comments.js';
import { AddApplicationFormFieldsToOrganizations20260314000000 } from './20260314000000-add-application-form-fields-to-organizations.js';
import { AddCommentStatusForModeration20260315000000 } from './20260315000000-add-comment-status-for-moderation.js';
import { CreateSchedulingTables20260316000000 } from './20260316000000-create-scheduling-tables.js';
import { AddDepartmentsStationsRoomsChairsAndEmployeeShiftChair20260316100000 } from './20260316100000-add-departments-stations-rooms-chairs-and-employee-shift-chair.js';
import { CreateOrganizationCompanyProfilesTable20260317000000 } from './20260317000000-create-organization-company-profiles-table.js';
import { AddFaxCoverImagesToCompanyProfile20260318000000 } from './20260318000000-add-fax-cover-images-to-company-profile.js';
import { UniqueCompanyNameCompanyProfile20260319000000 } from './20260319000000-unique-company-name-company-profile.js';
import { AllowMultipleDocsPerType20260319100000 } from './20260319100000-allow-multiple-docs-per-type.js';
import { ConvertVideoUrlToVideoUrlsJsonb20260319200000 } from './20260319200000-convert-video-url-to-video-urls-jsonb.js';
import { ConvertPdfColumnsToPdfFilesJsonb20260319300000 } from './20260319300000-convert-pdf-columns-to-pdf-files-jsonb.js';
import { SplitAddressIntoStructuredFields20260319400000 } from './20260319400000-split-address-into-structured-fields.js';
import { CreateComplianceDocumentsTables20260317500000 } from './20260317500000-create-compliance-documents-tables.js';
import { AddFeaturedVideoToBlogs20260324100000 } from './20260324100000-add-featured-video-to-blogs.js';
import { AddStructuredAddressToCompanyProfile20260326000000 } from './20260326000000-add-structured-address-to-company-profile.js';
import { AddIsSupervisorFieldToStaffTable20260327100000 } from './20260327100000-add-is_supervisor_field_to_staff_table.js';
import { CreateDocumentWorkflowTables20260329100000 } from './20260329100000-create-document-workflow-tables.js';
import { DropSupervisorNameEmailFromAssignments20260330100000 } from './20260330100000-drop-supervisor-name-email-from-assignments.js';
import { RemoveGridTemplateColumns20260331100000 } from './20260331100000-remove-grid-template-columns.js';
import { CreateDocumentFieldValues20260331110000 } from './20260331110000-create-document-field-values.js';
import { CreateDocumentWorkflowRoles20260401100000 } from './20260401100000-create-document-workflow-roles.js';
import { CreateRequirementDocumentTemplates20260401100001 } from './20260401100001-create-requirement-document-templates.js';
import { CreateDocumentTemplateUserAssignments20260401100002 } from './20260401100002-create-document-template-user-assignments.js';
import { AddDocumentTemplateIdsToReferrals20260403000001 } from './20260403000001-add-document-template-ids-to-referrals.js';
import { AddDepartmentConfigOptionsAndLayoutType20260406100000 } from './20260406100000-add-department-config-options-and-layout-type.js';
import { AddDynamicDepartmentEntities20260409100000 } from './20260409100000-add-dynamic-department-entities.js';
import { CreateEmployeeCalendarTables20260410100000 } from './20260410100000-create-employee-calendar-tables.js';
import { AddDateToAvailabilityRules20260410200000 } from './20260410200000-add-date-to-availability-rules.js';
import { AddScheduledDateToEmployeeShifts20260414100000 } from './20260414100000-add-scheduled-date-to-employee-shifts.js';
import { AddOfferDetailsToJobApplications20260414100000 } from './20260414100000-add-offer-details-to-job-applications.js';
import { AddDeclineReasonToJobApplications20260415200000 } from './20260415200000-add-decline-reason-to-job-applications.js';
import { AddInterviewDetailsAndIndexesToJobApplications20260416100000 } from './20260416100000-add-interview-details-and-indexes-to-job-applications.js';
import { CreateJobApplicationFieldValues20260416110000 } from './20260416110000-create-job-application-field-values.js';
import { CreateOfferLetterAssignmentTables20260416200000 } from './20260416200000-create-offer-letter-assignment-tables.js';
import { AddApplicantUserIdToJobApplications20260417100000 } from './20260417100000-add-applicant-user-id-to-job-applications.js';
import { AddUserFksForOrphanSafety20260418100000 } from './20260418100000-add-user-fks-for-orphan-safety.js';
import { CreateScheduledTaskTables20260420100000 } from './20260420100000-create-scheduled-task-tables.js';
import { AddApplicationFieldsSnapshotToJobPostings20260421000000 } from './20260421000000-add-application-fields-snapshot-to-job-postings.js';
import { AddSignatureAuditToOfferLetterFieldValues20260421100000 } from './20260421100000-add-signature-audit-to-offer-letter-field-values.js';
import { AddRoleToEmployeeShifts20260421200000 } from './20260421200000-add-role-to-employee-shifts.js';
import { AddPurposeToCompetencyTemplates20260422000002 } from './20260422000002-add-purpose-to-competency-templates.js';
import { AddTitlesToInserviceTrainings20260422100000 } from './20260422100000-add-titles-to-inservice-trainings.js';
import { AddHrNotesToJobApplications20260423100000 } from './20260423100000-add-hr-notes-to-job-applications.js';
import { AddStatusTimestampsToJobApplications20260423110000 } from './20260423110000-add-status-timestamps-to-job-applications.js';

type MigrationConstructor = new () => MigrationInterface;

export const migrations: MigrationConstructor[] = [
  CreateUsersTable20260101000000,
  AddGoogleIdToUsers20260128060000,
  CreateCreditPackagesTable20260129055907,
  AddPasswordChangedAtToUsers20260202040507,
  AddTemporaryPasswordFields20260202052121,
  CreateOrganizationsPatientsTables20260208000000,
  PatientsNullableUserIdAndOrganization20260209000001,
  CreateReferralTables20260209000002,
  BackfillReferralStatusAssigned20260210000001,
  BackfillReferralStatusFromSelectedOrgResponse20260210000002,
  CreateReferralDocumentsTable20260210000003,
  RemoveReferralStatusAndAssignmentOutcome20260212000001,
  MakeUsersPasswordNullable20260217000001,
  CreatePatientMedicationsTables20260218000001,
  AddRecordedByToMedicationAdministrations20260218000002,
  AddDeletedAtPatientMedications20260218000003,
  BackfillUsersEmailNotNull20260219000001,
  CreateStaffManagementTables20260219000001,
  SeedRolesTable20260219100000,
  AddStaffSystemRole20260219100000,
  SeedOrganizationTypesTable20260219100001,
  CreateOrganizationFeaturesTable20260219110000,
  LinkStaffRolePermissionsToOrganizationFeatures20260219110001,
  AddMedicationEmbedding20260223100000,
  CreateProviderRolesTable20260224100000,
  AlterEmployeesAndProfiles20260224100001,
  DropEmployeeRoleAndOnboardingStatus20260224100003,
  CreateHrDocumentTypesTable20260226100000,
  CreateEmployeeDocumentsTable20260227100000,
  CreateDocumentChunksAndVector20260227100001,
  AddDeletedAtEmployeeDocuments20260227100002,
  PartialUniqueEmployeeDocuments20260227100003,
  CreatePatientChatTables20260302000000,
  CreateRequirementTagsTables20260303110000,
  CreateEmployeeRequirementTagsTable20260303110001,
  CreateJobPostingsTable20260304000000,
  AddEmployeeIdToHrDocumentTypes20260304100000,
  EmployeeDocumentTypesNoOrg20260305100000,
  CreateInserviceTrainingsTable20260305120000,
  CreateRequirementInserviceTrainingsTable20260305120001,
  SeedGlobalHrDocumentTypes20260306100000,
  AddHasQuizAndPassingScoreToInserviceTrainings20260306120000,
  CreateInserviceQuizQuestionsTable20260306120001,
  CreateJobApplicationsTable20260307000000,
  CreateInserviceCompletionsAndQuizAttempts20260311100000,
  AddDisplayNameToUsers20260312000000,
  CreateBlogLikesAndComments20260312000001,
  AddGuestSupportToBlogLikesComments20260313000000,
  AddApplicationFormFieldsToOrganizations20260314000000,
  AddCommentStatusForModeration20260315000000,
  CreateSchedulingTables20260316000000,
  AddDepartmentsStationsRoomsChairsAndEmployeeShiftChair20260316100000,
  CreateOrganizationCompanyProfilesTable20260317000000,
  AddFaxCoverImagesToCompanyProfile20260318000000,
  UniqueCompanyNameCompanyProfile20260319000000,
  AllowMultipleDocsPerType20260319100000,
  ConvertVideoUrlToVideoUrlsJsonb20260319200000,
  ConvertPdfColumnsToPdfFilesJsonb20260319300000,
  SplitAddressIntoStructuredFields20260319400000,
  CreateComplianceDocumentsTables20260317500000,
  AddFeaturedVideoToBlogs20260324100000,
  AddStructuredAddressToCompanyProfile20260326000000,
  AddIsSupervisorFieldToStaffTable20260327100000,
  CreateDocumentWorkflowTables20260329100000,
  DropSupervisorNameEmailFromAssignments20260330100000,
  RemoveGridTemplateColumns20260331100000,
  CreateDocumentFieldValues20260331110000,
  CreateDocumentWorkflowRoles20260401100000,
  CreateRequirementDocumentTemplates20260401100001,
  CreateDocumentTemplateUserAssignments20260401100002,
  AddDocumentTemplateIdsToReferrals20260403000001,
  AddDepartmentConfigOptionsAndLayoutType20260406100000,
  AddDynamicDepartmentEntities20260409100000,
  CreateEmployeeCalendarTables20260410100000,
  AddDateToAvailabilityRules20260410200000,
  AddScheduledDateToEmployeeShifts20260414100000,
  AddOfferDetailsToJobApplications20260414100000,
  AddDeclineReasonToJobApplications20260415200000,
  AddInterviewDetailsAndIndexesToJobApplications20260416100000,
  CreateJobApplicationFieldValues20260416110000,
  CreateOfferLetterAssignmentTables20260416200000,
  AddApplicantUserIdToJobApplications20260417100000,
  AddUserFksForOrphanSafety20260418100000,
  CreateScheduledTaskTables20260420100000,
  AddApplicationFieldsSnapshotToJobPostings20260421000000,
  AddSignatureAuditToOfferLetterFieldValues20260421100000,
  AddRoleToEmployeeShifts20260421200000,
  AddPurposeToCompetencyTemplates20260422000002,
  AddTitlesToInserviceTrainings20260422100000,
  AddHrNotesToJobApplications20260423100000,
  AddStatusTimestampsToJobApplications20260423110000,
];
