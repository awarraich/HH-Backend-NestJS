import { Organization } from '../entities/organization.entity';

export class OrganizationSerializer {
  serialize(organization: Organization): any {
    return {
      id: organization.id,
      user_id: organization.user_id,
      organization_name: organization.organization_name,
      tax_id: organization.tax_id,
      registration_number: organization.registration_number,
      website: organization.website,
      description: organization.description,
      created_at: organization.created_at,
      updated_at: organization.updated_at,
      // Include relations if loaded
      ...(organization.user && {
        user: {
          id: organization.user.id,
          email: organization.user.email,
          firstName: organization.user.firstName,
          lastName: organization.user.lastName,
        },
      }),
      ...(organization.profile && {
        profile: this.serializeProfile(organization.profile),
      }),
      ...(organization.typeAssignments && organization.typeAssignments.length > 0 && {
        types: organization.typeAssignments.map((assignment) => ({
          id: assignment.organizationType?.id,
          name: assignment.organizationType?.name,
        })),
      }),
    };
  }

  serializeMany(organizations: Organization[]): any[] {
    return organizations.map((org) => this.serialize(org));
  }

  private serializeProfile(profile: any): any {
    if (!profile) return null;

    return {
      id: profile.id,
      organization_id: profile.organization_id,
      organization_type_id: profile.organization_type_id,
      address_line_1: profile.address_line_1,
      address_line_2: profile.address_line_2,
      zip_code_1: profile.zip_code_1,
      zip_code_2: profile.zip_code_2,
      phone_number: profile.phone_number,
      fax_number: profile.fax_number,
      npi_number: profile.npi_number,
      ein: profile.ein,
      ptin: profile.ptin,
      state_license: profile.state_license,
      state_license_expiration: profile.state_license_expiration,
      clia_number: profile.clia_number,
      clia_expiration: profile.clia_expiration,
      business_license: profile.business_license,
      business_license_expiration: profile.business_license_expiration,
      ftb: profile.ftb,
      administrator_name: profile.administrator_name,
      administrator_id: profile.administrator_id,
      administrator_expiration: profile.administrator_expiration,
      designee_administrator_name: profile.designee_administrator_name,
      designee_administrator_id: profile.designee_administrator_id,
      designee_administrator_expiration: profile.designee_administrator_expiration,
      dpcs_don_name: profile.dpcs_don_name,
      dpcs_don_id: profile.dpcs_don_id,
      dpcs_don_license: profile.dpcs_don_license,
      dpcs_don_expiration: profile.dpcs_don_expiration,
      designee_dpcs_don_name: profile.designee_dpcs_don_name,
      designee_dpcs_don_id: profile.designee_dpcs_don_id,
      designee_dpcs_don_license: profile.designee_dpcs_don_license,
      designee_dpcs_don_expiration: profile.designee_dpcs_don_expiration,
      medical_director_name: profile.medical_director_name,
      medical_director_id: profile.medical_director_id,
      medical_director_expiration: profile.medical_director_expiration,
      admin_name: profile.admin_name,
      admin_license: profile.admin_license,
      admin_expiration: profile.admin_expiration,
      rcfe_number: profile.rcfe_number,
      rcfe_license: profile.rcfe_license,
      rcfe_expiration: profile.rcfe_expiration,
      pharmacist_name: profile.pharmacist_name,
      pharmacist_license: profile.pharmacist_license,
      pharmacist_license_expiration: profile.pharmacist_license_expiration,
      lab_owner_name: profile.lab_owner_name,
      lab_license: profile.lab_license,
      lab_license_expiration: profile.lab_license_expiration,
      created_at: profile.created_at,
      updated_at: profile.updated_at,
    };
  }
}

