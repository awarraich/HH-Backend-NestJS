/**
 * E-signature consent text versions. Each time the wording changes we
 * append a new entry and bump the default; historical signatures still
 * reference the version they actually saw so we can reproduce the exact
 * consent prose a signer agreed to years later.
 *
 * ESIGN / UETA compliance: the applicant (or role filler) must see and
 * accept this text before their canvas signature is considered binding.
 */

export interface ESignConsentVersion {
  version: string;
  text: string;
}

export const APPLICANT_OFFER_LETTER_CONSENT_VERSIONS: ESignConsentVersion[] = [
  {
    version: 'applicant-offer-v1',
    text:
      'By signing below I agree that my electronic signature is the legal equivalent of my handwritten signature on this offer letter. I consent to conduct this transaction by electronic means and understand that this agreement is binding.',
  },
];

export const ROLE_FILLER_OFFER_LETTER_CONSENT_VERSIONS: ESignConsentVersion[] = [
  {
    version: 'role-filler-offer-v1',
    text:
      'By signing below I agree that my electronic signature is the legal equivalent of my handwritten signature on this offer letter and that I am authorised to sign in the role shown. I consent to the use of electronic records and signatures for this document.',
  },
];

export const CURRENT_APPLICANT_OFFER_LETTER_CONSENT =
  APPLICANT_OFFER_LETTER_CONSENT_VERSIONS[
    APPLICANT_OFFER_LETTER_CONSENT_VERSIONS.length - 1
  ];

export const CURRENT_ROLE_FILLER_OFFER_LETTER_CONSENT =
  ROLE_FILLER_OFFER_LETTER_CONSENT_VERSIONS[
    ROLE_FILLER_OFFER_LETTER_CONSENT_VERSIONS.length - 1
  ];

/**
 * Look up a consent version by id. Returns null when the id is unknown —
 * callers should treat that as "client sent an unrecognised version" and
 * reject the signature rather than silently accepting it.
 */
export function findApplicantOfferLetterConsent(
  version: string,
): ESignConsentVersion | null {
  return (
    APPLICANT_OFFER_LETTER_CONSENT_VERSIONS.find((v) => v.version === version) ??
    null
  );
}

export function findRoleFillerOfferLetterConsent(
  version: string,
): ESignConsentVersion | null {
  return (
    ROLE_FILLER_OFFER_LETTER_CONSENT_VERSIONS.find(
      (v) => v.version === version,
    ) ?? null
  );
}
