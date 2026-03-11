import { Employee } from '../entities/employee.entity';

export class EmployeeSerializer {
  serialize(employee: Employee): any {
    return {
      id: employee.id,
      user_id: employee.user_id,
      organization_id: employee.organization_id,
      status: employee.status,
      employment_type: employee.employment_type,
      notes: employee.notes,
      provider_role_id: employee.provider_role_id,
      requirement_tag_ids: this.getRequirementTagIds(employee),
      start_date: employee.start_date,
      end_date: employee.end_date,
      department: employee.department,
      position_title: employee.position_title,
      created_at: employee.created_at,
      updated_at: employee.updated_at,
      ...(employee.user && {
        user: {
          id: employee.user.id,
          email: employee.user.email,
          firstName: employee.user.firstName,
          lastName: employee.user.lastName,
          is_active: employee.user.is_active,
        },
      }),
      ...(employee.organization && {
        organization: {
          id: employee.organization.id,
          organization_name: employee.organization.organization_name,
        },
      }),
      ...(employee.profile && {
        profile: this.serializeProfile(employee.profile),
      }),
      ...(employee.providerRole && {
        provider_role: {
          id: employee.providerRole.id,
          code: employee.providerRole.code,
          name: employee.providerRole.name,
        },
      }),
    };
  }

  serializeMany(employees: Employee[]): any[] {
    return employees.map((employee) => this.serialize(employee));
  }

  private getRequirementTagIds(employee: Employee): string[] {
    if (!employee.employeeRequirementTags?.length) return [];
    return employee.employeeRequirementTags.map((ert) => ert.requirement_tag_id);
  }

  private serializeProfile(profile: any): any {
    if (!profile) return null;

    return {
      id: profile.id,
      employee_id: profile.employee_id,
      name: profile.name,
      profile_image: profile.profile_image,
      address: profile.address,
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
