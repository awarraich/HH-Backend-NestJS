/**
 * E-signature consent text for competency template signers (employee and
 * supervisor / other workflow roles). Mirrors the structure of the
 * job-management consent file — when the wording changes, append a new
 * version so historical signatures keep referencing the exact text the
 * signer actually saw.
 */

export interface CompetencyESignConsentVersion {
  version: string;
  text: string;
}

export const COMPETENCY_ROLE_FILLER_CONSENT_VERSIONS: CompetencyESignConsentVersion[] = [
  {
    version: 'competency-role-filler-v1',
    text:
      'By signing below I agree that my electronic signature is the legal equivalent of my handwritten signature on this competency document and that I am authorised to sign in the role shown. I consent to the use of electronic records and signatures for this document.',
  },
];

export const CURRENT_COMPETENCY_ROLE_FILLER_CONSENT =
  COMPETENCY_ROLE_FILLER_CONSENT_VERSIONS[
    COMPETENCY_ROLE_FILLER_CONSENT_VERSIONS.length - 1
  ];

export function findCompetencyRoleFillerConsent(
  version: string,
): CompetencyESignConsentVersion | null {
  return (
    COMPETENCY_ROLE_FILLER_CONSENT_VERSIONS.find((v) => v.version === version) ??
    null
  );
}
