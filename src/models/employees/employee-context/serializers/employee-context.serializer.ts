import { Employee } from '../../entities/employee.entity';
import { EmployeeProfile } from '../../entities/employee-profile.entity';

export interface OrganizationContextItem {
  organization_id: string;
  organization_name: string | null;
  employee_status: string;
  is_active_context: boolean;
  provider_role?: { id: string; code: string; name: string } | null;
}

export class EmployeeContextSerializer {
  serializeContext(
    employee: Employee,
    organizations: OrganizationContextItem[],
  ): {
    employee: {
      id: string;
      user_id: string;
      user: {
        id: string;
        email: string;
        firstName: string;
        lastName: string;
        is_active: boolean;
      } | null;
      profile: ReturnType<EmployeeContextSerializer['serializeProfile']>;
    };
    organizations: OrganizationContextItem[];
  } {
    return {
      employee: {
        id: employee.id,
        user_id: employee.user_id,
        user: employee.user
          ? {
              id: employee.user.id,
              email: employee.user.email,
              firstName: employee.user.firstName,
              lastName: employee.user.lastName,
              is_active: employee.user.is_active,
            }
          : null,
        profile: this.serializeProfile(employee.profile),
      },
      organizations,
    };
  }

  private serializeProfile(profile: EmployeeProfile | null | undefined): {
    id: string;
    employee_id: string;
    name: string;
    profile_image: string | null;
    address_line_1: string | null;
    address_line_2: string | null;
    city: string | null;
    state: string | null;
    phone_number: string | null;
    gender: string | null;
    age: number | null;
    date_of_birth: Date | null;
    specialization: string | null;
    years_of_experience: number | null;
    certification: string | null;
    board_certifications: Record<string, unknown> | null;
    emergency_contact: Record<string, unknown> | null;
    created_at: Date;
    updated_at: Date;
  } | null {
    if (!profile) return null;
    return {
      id: profile.id,
      employee_id: profile.employee_id,
      name: profile.name,
      profile_image: profile.profile_image,
      address_line_1: profile.address_line_1,
      address_line_2: profile.address_line_2,
      city: profile.city,
      state: profile.state,
      phone_number: profile.phone_number,
      gender: profile.gender,
      age: profile.age,
      date_of_birth: profile.date_of_birth,
      specialization: profile.specialization,
      years_of_experience: profile.years_of_experience,
      certification: profile.certification,
      board_certifications: profile.board_certifications,
      emergency_contact: profile.emergency_contact,
      created_at: profile.created_at,
      updated_at: profile.updated_at,
    };
  }
}
