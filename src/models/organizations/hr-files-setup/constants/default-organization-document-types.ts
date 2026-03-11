/**
 * Default HR document types seeded for each new organization (20 types).
 * Used when an organization is created.
 */
export interface DefaultDocumentTypeRow {
  code: string;
  name: string;
  has_expiration: boolean;
  is_required: boolean;
  category: string | null;
  sort_order: number;
}

export const DEFAULT_ORGANIZATION_DOCUMENT_TYPES: DefaultDocumentTypeRow[] = [
  {
    code: 'ID',
    name: 'Government ID / Passport',
    has_expiration: false,
    is_required: true,
    category: 'Identity',
    sort_order: 0,
  },
  {
    code: 'RESUME',
    name: 'Resume / CV',
    has_expiration: false,
    is_required: false,
    category: 'Employment',
    sort_order: 1,
  },
  {
    code: 'LICENSE',
    name: 'Professional License',
    has_expiration: true,
    is_required: false,
    category: 'Credentials',
    sort_order: 2,
  },
  {
    code: 'CERTIFICATION',
    name: 'Professional Certification',
    has_expiration: true,
    is_required: false,
    category: 'Credentials',
    sort_order: 3,
  },
  {
    code: 'DEGREE',
    name: 'Degree / Diploma',
    has_expiration: false,
    is_required: false,
    category: 'Education',
    sort_order: 4,
  },
  {
    code: 'I9',
    name: 'I-9 Form',
    has_expiration: false,
    is_required: true,
    category: 'Compliance',
    sort_order: 5,
  },
  {
    code: 'W4',
    name: 'W-4 Form',
    has_expiration: false,
    is_required: false,
    category: 'Tax',
    sort_order: 6,
  },
  {
    code: 'DIRECT_DEPOSIT',
    name: 'Direct Deposit Form',
    has_expiration: false,
    is_required: false,
    category: 'Payroll',
    sort_order: 7,
  },
  {
    code: 'EMERGENCY_CONTACT',
    name: 'Emergency Contact',
    has_expiration: false,
    is_required: false,
    category: 'HR',
    sort_order: 8,
  },
  {
    code: 'OFFER_LETTER',
    name: 'Offer Letter',
    has_expiration: false,
    is_required: false,
    category: 'Employment',
    sort_order: 9,
  },
  {
    code: 'CPR',
    name: 'CPR Certification',
    has_expiration: true,
    is_required: false,
    category: 'Credentials',
    sort_order: 10,
  },
  {
    code: 'FIRST_AID',
    name: 'First Aid Certification',
    has_expiration: true,
    is_required: false,
    category: 'Credentials',
    sort_order: 11,
  },
  {
    code: 'DRIVERS_LICENSE',
    name: "Driver's License",
    has_expiration: true,
    is_required: false,
    category: 'Identity',
    sort_order: 12,
  },
  {
    code: 'INSURANCE',
    name: 'Insurance Card',
    has_expiration: true,
    is_required: false,
    category: 'Benefits',
    sort_order: 13,
  },
  {
    code: 'VACCINATION',
    name: 'Vaccination Record',
    has_expiration: false,
    is_required: false,
    category: 'Health',
    sort_order: 14,
  },
  {
    code: 'BACKGROUND_CHECK',
    name: 'Background Check',
    has_expiration: false,
    is_required: false,
    category: 'Compliance',
    sort_order: 15,
  },
  {
    code: 'RIGHT_TO_WORK',
    name: 'Right to Work',
    has_expiration: false,
    is_required: true,
    category: 'Compliance',
    sort_order: 16,
  },
  {
    code: 'TRAINING_CERT',
    name: 'Training Certificate',
    has_expiration: true,
    is_required: false,
    category: 'Credentials',
    sort_order: 17,
  },
  {
    code: 'NDA',
    name: 'NDA / Confidentiality',
    has_expiration: false,
    is_required: false,
    category: 'Legal',
    sort_order: 18,
  },
  {
    code: 'OTHER',
    name: 'Other Document',
    has_expiration: false,
    is_required: false,
    category: 'Other',
    sort_order: 19,
  },
];
