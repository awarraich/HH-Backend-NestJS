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
import { User } from '../../authentication/entities/user.entity';
import { StaffRole } from './staff-management/entities/staff-role.entity';
import { OrganizationStaff } from './staff-management/entities/organization-staff.entity';
import { OrganizationStaffRolePermission } from './staff-management/entities/organization-staff-role-permission.entity';
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
import { OrganizationTypesController } from './controllers/organization-types.controller';
import { ReferralsController } from './controllers/referrals.controller';
import { ReferralOrganizationsController } from './controllers/referral-organizations.controller';
import { OrganizationStaffController } from './staff-management/controllers/organization-staff.controller';
import { OrganizationStaffService } from './staff-management/services/organization-staff.service';
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
      StaffRole,
      OrganizationStaff,
      OrganizationStaffRolePermission,
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
  ],
  controllers: [
    OrganizationsController,
    OrganizationTypesController,
    ReferralsController,
    ReferralOrganizationsController,
    OrganizationStaffController,
  ],
  providers: [
    OrganizationsService,
    OrganizationRoleService,
    OrganizationPermissionService,
    ReferralsService,
    ReferralMessagesService,
    ReferralDocumentStorageService,
    OrganizationStaffService,
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
  ],
})
export class OrganizationsModule {}
