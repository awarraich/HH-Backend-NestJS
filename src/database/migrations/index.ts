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
import { SeedRolesTable20260219100000 } from './20260219100000-seed-roles-table.js';
import { SeedOrganizationTypesTable20260219100001 } from './20260219100001-seed-organization-types-table.js';
import { CreateBlogsTable1708000000000 } from './20260220000000-create-blogs-table.js';
import { CreatePatientChatTables20260302000000 } from './20260302000000-create-patient-chat-tables.js';
import { CreateJobPostingsTable20260304000000 } from './20260304000000-create-job-postings-table.js';
import { CreateJobApplicationsTable20260307000000 } from './20260307000000-create-job-applications-table.js';
import { CreateInserviceCompletionsAndQuizAttempts20260311100000 } from './20260311100000-create-inservice-completions-and-quiz-attempts.js';
import { AddDisplayNameToUsers20260312000000 } from './20260312000000-add-display-name-to-users.js';
import { CreateBlogLikesAndComments20260312000001 } from './20260312000001-create-blog-likes-and-comments.js';
import { AddGuestSupportToBlogLikesComments20260313000000 } from './20260313000000-add-guest-support-to-blog-likes-comments.js';
import { AddApplicationFormFieldsToOrganizations20260314000000 } from './20260314000000-add-application-form-fields-to-organizations.js';
import { AddCommentStatusForModeration20260315000000 } from './20260315000000-add-comment-status-for-moderation.js';
import { CreateOrganizationCompanyProfilesTable20260317000000 } from './20260317000000-create-organization-company-profiles-table.js';
import { AddFaxCoverImagesToCompanyProfile20260318000000 } from './20260318000000-add-fax-cover-images-to-company-profile.js';
import { UniqueCompanyNameCompanyProfile20260319000000 } from './20260319000000-unique-company-name-company-profile.js';

/** Type for migration class constructors (TypeORM instantiates these at runtime). */
type MigrationConstructor = new () => MigrationInterface;

/**
 * All migrations in run order. Used by TypeORM at startup when DB_MIGRATIONS_RUN=true
 * so that migration files are part of the app bundle and always run.
 */
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
  SeedRolesTable20260219100000,
  SeedOrganizationTypesTable20260219100001,
  CreateBlogsTable1708000000000,
  CreatePatientChatTables20260302000000,
  CreateJobPostingsTable20260304000000,
  CreateJobApplicationsTable20260307000000,
  CreateInserviceCompletionsAndQuizAttempts20260311100000,
  AddDisplayNameToUsers20260312000000,
  CreateBlogLikesAndComments20260312000001,
  AddGuestSupportToBlogLikesComments20260313000000,
  AddApplicationFormFieldsToOrganizations20260314000000,
  AddCommentStatusForModeration20260315000000,
  CreateOrganizationCompanyProfilesTable20260317000000,
  AddFaxCoverImagesToCompanyProfile20260318000000,
  UniqueCompanyNameCompanyProfile20260319000000,
];
