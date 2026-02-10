import { Referral } from '../entities/referral.entity';
import { ReferralOrganization } from '../entities/referral-organization.entity';

export class ReferralSerializer {
  serialize(referral: Referral): any {
    const patient = referral.patient;
    const patientProfile = patient?.profile;
    const sendingOrg = referral.sendingOrganization;
    const sendingOrgProfile = sendingOrg?.profile;

    return {
      id: referral.id,
      public_id: referral.public_id,
      organization_type_id: referral.organization_type_id,
      organization_type_name: (referral as any).organizationType?.name,
      status: referral.status,
      urgency: referral.urgency,
      patient_id: referral.patient_id,
      patient_name: patientProfile?.name ?? null,
      sending_organization_id: referral.sending_organization_id,
      sending_organization_name: sendingOrg?.organization_name ?? null,
      insurance_provider: referral.insurance_provider,
      estimated_cost: referral.estimated_cost,
      notes: referral.notes,
      level_of_care: referral.level_of_care,
      date_responded: referral.date_responded,
      selected_organization_id: referral.selected_organization_id,
      created_at: referral.created_at,
      updated_at: referral.updated_at,
      ...(referral.referralOrganizations && referral.referralOrganizations.length > 0 && {
        receiving_orgs: referral.referralOrganizations.map((ro) => this.serializeReferralOrg(ro)),
      }),
    };
  }

  serializeMany(referrals: Referral[]): any[] {
    return referrals.map((r) => this.serialize(r));
  }

  private serializeReferralOrg(ro: ReferralOrganization): any {
    const org = ro.organization;
    const profile = org?.profile;
    return {
      org_id: ro.organization_id,
      org_name: org?.organization_name ?? null,
      response_status: ro.response_status,
      response_date: ro.response_date,
      proposed_terms: ro.proposed_terms,
      notes: ro.notes,
      assignment_outcome: ro.assignment_outcome,
    };
  }
}
