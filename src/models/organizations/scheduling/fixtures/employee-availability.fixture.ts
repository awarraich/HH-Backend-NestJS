export type AvailabilityType = 'specific' | 'recurring';
export type AvailabilityStatus = 'available' | 'unavailable' | 'tentative' | 'booked';
export type WeekdayCode = 'MON' | 'TUE' | 'WED' | 'THU' | 'FRI' | 'SAT' | 'SUN';

export interface EmployeeAvailabilityRecord {
  id: string;
  employee_id: string;
  organization_id: string | null;
  availability_type: AvailabilityType;
  /** Set when availability_type === 'specific'. */
  date: string | null;
  /** Set when availability_type === 'recurring'. */
  recurring_start_date: string | null;
  recurring_end_date: string | null;
  days_of_week: WeekdayCode[] | null;
  /** 'HH:MM' (24-hour). Naive — no timezone. */
  start_time: string;
  end_time: string;
  status: AvailabilityStatus;
  max_bookings: number;
  current_bookings: number;
  notes: string | null;
}

/**
 * A small set of records using documented dummy IDs. Useful for smoke-testing
 * tools without needing real employees in the database.
 */
const DEMO_ORGANIZATION_ID = 'b3c22a1f-2b32-4f8f-b4bf-007ae1eda7db';

// Real employee IDs from organization 29053b9b-...
const ANIQ_JAVED      = '14127590-3a22-40a2-8742-7626d6b066dd';
const EMPLOYEE_2      = '7be0a441-2085-417c-825b-573c28e3aeee';
const EMPLOYEE_3      = '591b022b-cb8f-4a38-a66b-fd75e2ee04cb';
const EMPLOYEE_4      = '795aa994-9676-456a-9fc9-eacc3b6a37a8';
const EMPLOYEE_5      = 'f657bf38-99b0-4adf-a4bb-9c06782b2769';
const EMPLOYEE_6      = '04ba7310-e99d-46fc-9f25-0c46ca162522';

export const DEMO_AVAILABILITY_FIXTURE: EmployeeAvailabilityRecord[] = [
  // ----- Aniq Javed: full weekday coverage, AM + PM windows -----
  {
    id: 'fix-aniq-am',
    employee_id: ANIQ_JAVED,
    organization_id: DEMO_ORGANIZATION_ID,
    availability_type: 'recurring',
    date: null,
    recurring_start_date: '2026-01-01',
    recurring_end_date: '2026-12-31',
    days_of_week: ['MON', 'TUE', 'WED', 'THU', 'FRI'],
    start_time: '00:00',
    end_time: '12:00',
    status: 'available',
    max_bookings: 1,
    current_bookings: 0,
    notes: 'Aniq — weekday morning (covers AM SHIFT after UTC conversion)',
  },
  {
    id: 'fix-aniq-pm',
    employee_id: ANIQ_JAVED,
    organization_id: DEMO_ORGANIZATION_ID,
    availability_type: 'recurring',
    date: null,
    recurring_start_date: '2026-01-01',
    recurring_end_date: '2026-12-31',
    days_of_week: ['MON', 'TUE', 'WED', 'THU', 'FRI'],
    start_time: '08:00',
    end_time: '20:00',
    status: 'available',
    max_bookings: 1,
    current_bookings: 0,
    notes: 'Aniq — full weekday day window',
  },

  // ----- Employee 2: weekday AM coverage -----
  {
    id: 'fix-emp2-am',
    employee_id: EMPLOYEE_2,
    organization_id: DEMO_ORGANIZATION_ID,
    availability_type: 'recurring',
    date: null,
    recurring_start_date: '2026-01-01',
    recurring_end_date: '2026-12-31',
    days_of_week: ['MON', 'TUE', 'WED', 'THU', 'FRI'],
    start_time: '00:00',
    end_time: '11:00',
    status: 'available',
    max_bookings: 1,
    current_bookings: 0,
    notes: 'Employee 2 — weekday AM (covers AM SHIFT 02:00-10:00 UTC)',
  },

  // ----- Employee 3: Tue/Thu daytime -----
  {
    id: 'fix-emp3-day',
    employee_id: EMPLOYEE_3,
    organization_id: DEMO_ORGANIZATION_ID,
    availability_type: 'recurring',
    date: null,
    recurring_start_date: '2026-01-01',
    recurring_end_date: '2026-12-31',
    days_of_week: ['TUE', 'THU'],
    start_time: '12:00',
    end_time: '20:00',
    status: 'available',
    max_bookings: 1,
    current_bookings: 0,
    notes: 'Employee 3 — Tue/Thu afternoon to evening',
  },

  // ----- Employee 4: weekend tentative -----
  {
    id: 'fix-emp4-weekend',
    employee_id: EMPLOYEE_4,
    organization_id: DEMO_ORGANIZATION_ID,
    availability_type: 'recurring',
    date: null,
    recurring_start_date: '2026-01-01',
    recurring_end_date: '2026-12-31',
    days_of_week: ['SAT', 'SUN'],
    start_time: '08:00',
    end_time: '16:00',
    status: 'tentative',
    max_bookings: 1,
    current_bookings: 0,
    notes: 'Employee 4 — weekend on-call (tentative)',
  },

  // ----- Employee 5: full week, narrow midday window -----
  {
    id: 'fix-emp5-midday',
    employee_id: EMPLOYEE_5,
    organization_id: DEMO_ORGANIZATION_ID,
    availability_type: 'recurring',
    date: null,
    recurring_start_date: '2026-01-01',
    recurring_end_date: '2026-12-31',
    days_of_week: ['MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT'],
    start_time: '11:00',
    end_time: '15:00',
    status: 'available',
    max_bookings: 1,
    current_bookings: 0,
    notes: 'Employee 5 — narrow midday window (does not cover AM/NOC shifts)',
  },

  // ----- Employee 6: one-time coverage on a specific date -----
  {
    id: 'fix-emp6-specific',
    employee_id: EMPLOYEE_6,
    organization_id: DEMO_ORGANIZATION_ID,
    availability_type: 'specific',
    date: '2026-04-07',
    recurring_start_date: null,
    recurring_end_date: null,
    days_of_week: null,
    start_time: '00:00',
    end_time: '12:00',
    status: 'available',
    max_bookings: 1,
    current_bookings: 0,
    notes: 'Employee 6 — one-time coverage on 2026-04-07 (covers AM SHIFT)',
  },
];

/**
 * Deterministic per-employee generator. Lets any real employee from the
 * database surface fake availability so MCP tools work end-to-end without
 * pre-seeded rows. Output is identical for the same employee_id.
 */
export function generateAvailabilityForEmployee(
  employeeId: string,
  organizationId: string | null = null,
): EmployeeAvailabilityRecord[] {
  return [
    {
      id: `gen-${employeeId}-1`,
      employee_id: employeeId,
      organization_id: organizationId,
      availability_type: 'recurring',
      date: null,
      recurring_start_date: '2026-01-01',
      recurring_end_date: '2026-12-31',
      days_of_week: ['MON', 'TUE', 'WED', 'THU', 'FRI'],
      start_time: '09:00',
      end_time: '17:00',
      status: 'available',
      max_bookings: 1,
      current_bookings: 0,
      notes: 'Generated weekday availability',
    },
    {
      id: `gen-${employeeId}-2`,
      employee_id: employeeId,
      organization_id: organizationId,
      availability_type: 'recurring',
      date: null,
      recurring_start_date: '2026-01-01',
      recurring_end_date: '2026-12-31',
      days_of_week: ['SAT'],
      start_time: '10:00',
      end_time: '14:00',
      status: 'tentative',
      max_bookings: 1,
      current_bookings: 0,
      notes: 'Generated weekend on-call window',
    },
  ];
}
