import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { OrganizationRepository } from '../../../models/organizations/repositories/organization.repository';
import { Patient } from '../../../models/patients/entities/patient.entity';
import { Provider } from '../../../models/providers/entities/provider.entity';
import { Employee } from '../../../models/employees/entities/employee.entity';
import { Admin } from '../../../models/admins/entities/admin.entity';

export interface OnboardingStatusResponse {
  currentStep: string;
  nextAction: string;
  redirectPath?: string;
  requiresAction: boolean;
  details: {
    hasRole: boolean;
    role?: string;
    hasOrganizationType?: boolean;
    organizationType?: { id: number; name: string };
    profileStatus?: 'pending' | 'in_progress' | 'completed';
    onboardingStatus?: 'PENDING' | 'COMPLETED';
  };
}

@Injectable()
export class OnboardingStatusService {
  private readonly logger = new Logger(OnboardingStatusService.name);

  constructor(
    private organizationRepository: OrganizationRepository,
    @InjectRepository(Patient)
    private patientRepository: Repository<Patient>,
    @InjectRepository(Provider)
    private providerRepository: Repository<Provider>,
    @InjectRepository(Employee)
    private employeeRepository: Repository<Employee>,
    @InjectRepository(Admin)
    private adminRepository: Repository<Admin>,
  ) {}

  async getOnboardingStatus(
    userId: string,
    roles: string[],
  ): Promise<OnboardingStatusResponse> {
    try {
      const normalizedRoles = roles.map((r) => r.toUpperCase());

    if (normalizedRoles.includes('ADMIN')) {
      return {
        currentStep: 'admin',
        nextAction: 'navigate_to_admin',
        redirectPath: '/admin',
        requiresAction: false,
        details: {
          hasRole: true,
          role: 'ADMIN',
        },
      };
    }

    if (normalizedRoles.length === 0) {
      return {
        currentStep: 'role_selection',
        nextAction: 'select_role',
        redirectPath: '/onboarding/role-selection',
        requiresAction: true,
        details: {
          hasRole: false,
        },
      };
    }

    if (normalizedRoles.includes('ORGANIZATION')) {
      return this.getOrganizationOnboardingStatus(userId);
    }

    if (normalizedRoles.includes('PATIENT')) {
      return this.getPatientOnboardingStatus(userId);
    }

    if (normalizedRoles.includes('PROVIDER')) {
      return this.getProviderOnboardingStatus(userId);
    }

    if (normalizedRoles.includes('EMPLOYEE')) {
      return this.getEmployeeOnboardingStatus(userId);
    }

    return {
      currentStep: 'profile_setup',
      nextAction: 'complete_profile',
      redirectPath: '/onboarding/profile',
      requiresAction: true,
      details: {
        hasRole: true,
        role: normalizedRoles[0],
      },
    };
    } catch (error) {
      this.logger.error(
        `Error getting onboarding status for user ${userId}`,
        error,
      );
      throw error;
    }
  }

  private async getOrganizationOnboardingStatus(
    userId: string,
  ): Promise<OnboardingStatusResponse> {
    const organization = await this.organizationRepository.findByUserId(userId);

    if (!organization) {
      return {
        currentStep: 'organization_setup',
        nextAction: 'create_organization',
        redirectPath: '/onboarding/organization/create',
        requiresAction: true,
        details: {
          hasRole: true,
          role: 'ORGANIZATION',
          hasOrganizationType: false,
        },
      };
    }

    const hasOrganizationType =
      organization.typeAssignments &&
      organization.typeAssignments.length > 0;

    if (!hasOrganizationType) {
      return {
        currentStep: 'organization_type_selection',
        nextAction: 'select_organization_type',
        redirectPath: '/onboarding/organization/select-type',
        requiresAction: true,
        details: {
          hasRole: true,
          role: 'ORGANIZATION',
          hasOrganizationType: false,
        },
      };
    }

    const organizationType = organization.typeAssignments[0].organizationType
      ? {
          id: organization.typeAssignments[0].organizationType.id,
          name: organization.typeAssignments[0].organizationType.name,
        }
      : undefined;

    let profileStatus: 'pending' | 'in_progress' | 'completed' = 'pending';
    if (organization.profile) {
      const hasMinimumFields =
        organization.profile.address_line_1 &&
        organization.profile.phone_number &&
        organization.profile.organization_type_id;

      profileStatus = hasMinimumFields ? 'completed' : 'in_progress';
    }

    if (profileStatus === 'pending' || profileStatus === 'in_progress') {
      return {
        currentStep: 'organization_profile',
        nextAction: 'complete_organization_profile',
        redirectPath: '/onboarding/organization/profile',
        requiresAction: true,
        details: {
          hasRole: true,
          role: 'ORGANIZATION',
          hasOrganizationType: true,
          organizationType,
          profileStatus,
        },
      };
    }

    return {
      currentStep: 'completed',
      nextAction: 'navigate_to_dashboard',
      redirectPath: '/organization/dashboard',
      requiresAction: false,
      details: {
        hasRole: true,
        role: 'ORGANIZATION',
        hasOrganizationType: true,
        organizationType,
        profileStatus: 'completed',
      },
    };
  }

  private async getPatientOnboardingStatus(
    userId: string,
  ): Promise<OnboardingStatusResponse> {
    const patient = await this.patientRepository.findOne({
      where: { user_id: userId },
      relations: ['profile'],
    });

    if (!patient || !patient.profile) {
      return {
        currentStep: 'patient_profile',
        nextAction: 'create_patient_profile',
        redirectPath: '/onboarding/patient/profile',
        requiresAction: true,
        details: {
          hasRole: true,
          role: 'PATIENT',
          onboardingStatus: 'PENDING',
        },
      };
    }

    const onboardingStatus = patient.profile.onboarding_status || 'PENDING';

    if (onboardingStatus === 'PENDING') {
      return {
        currentStep: 'patient_profile',
        nextAction: 'complete_patient_profile',
        redirectPath: '/onboarding/patient/profile',
        requiresAction: true,
        details: {
          hasRole: true,
          role: 'PATIENT',
          onboardingStatus: 'PENDING',
        },
      };
    }

    return {
      currentStep: 'completed',
      nextAction: 'navigate_to_dashboard',
      redirectPath: '/patient/dashboard',
      requiresAction: false,
      details: {
        hasRole: true,
        role: 'PATIENT',
        onboardingStatus: 'COMPLETED',
      },
    };
  }

  private async getProviderOnboardingStatus(
    userId: string,
  ): Promise<OnboardingStatusResponse> {
    const provider = await this.providerRepository.findOne({
      where: { user_id: userId },
      relations: ['profile'],
    });

    if (!provider || !provider.profile) {
      return {
        currentStep: 'provider_profile',
        nextAction: 'create_provider_profile',
        redirectPath: '/onboarding/provider/profile',
        requiresAction: true,
        details: {
          hasRole: true,
          role: 'PROVIDER',
          onboardingStatus: 'PENDING',
        },
      };
    }

    const onboardingStatus = provider.profile.onboarding_status || 'PENDING';

    if (onboardingStatus === 'PENDING') {
      return {
        currentStep: 'provider_profile',
        nextAction: 'complete_provider_profile',
        redirectPath: '/onboarding/provider/profile',
        requiresAction: true,
        details: {
          hasRole: true,
          role: 'PROVIDER',
          onboardingStatus: 'PENDING',
        },
      };
    }

    return {
      currentStep: 'completed',
      nextAction: 'navigate_to_dashboard',
      redirectPath: '/provider/dashboard',
      requiresAction: false,
      details: {
        hasRole: true,
        role: 'PROVIDER',
        onboardingStatus: 'COMPLETED',
      },
    };
  }

  private async getEmployeeOnboardingStatus(
    userId: string,
  ): Promise<OnboardingStatusResponse> {
    const employee = await this.employeeRepository.findOne({
      where: { user_id: userId },
      relations: ['profile'],
    });

    if (!employee || !employee.profile) {
      return {
        currentStep: 'employee_profile',
        nextAction: 'create_employee_profile',
        redirectPath: '/onboarding/employee/profile',
        requiresAction: true,
        details: {
          hasRole: true,
          role: 'EMPLOYEE',
          onboardingStatus: 'PENDING',
        },
      };
    }

    const onboardingStatus = employee.profile.onboarding_status || 'PENDING';

    if (onboardingStatus === 'PENDING') {
      return {
        currentStep: 'employee_profile',
        nextAction: 'complete_employee_profile',
        redirectPath: '/onboarding/employee/profile',
        requiresAction: true,
        details: {
          hasRole: true,
          role: 'EMPLOYEE',
          onboardingStatus: 'PENDING',
        },
      };
    }

    return {
      currentStep: 'completed',
      nextAction: 'navigate_to_dashboard',
      redirectPath: '/employee/dashboard',
      requiresAction: false,
      details: {
        hasRole: true,
        role: 'EMPLOYEE',
        onboardingStatus: 'COMPLETED',
      },
    };
  }
}
