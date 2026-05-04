import { z } from 'zod';

/** YYYY-MM-DD date string. */
export const DateOnly = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}$/, 'Date must be in YYYY-MM-DD format');

/** HH:MM[:SS] time-of-day string. */
export const TimeOnly = z
  .string()
  .regex(
    /^([01]\d|2[0-3]):[0-5]\d(:[0-5]\d)?$/,
    'Time must be in HH:MM or HH:MM:SS (24h) format',
  );

/** 0=Sunday … 6=Saturday */
export const DayOfWeek = z
  .number()
  .int()
  .min(0)
  .max(6)
  .describe('Day of week — 0=Sunday, 1=Monday, … 6=Saturday');

export const AvailabilityRuleOutput = z.object({
  id: z.string(),
  dayOfWeek: z.number().nullable(),
  date: z.string().nullable(),
  startTime: z.string(),
  endTime: z.string(),
  isAvailable: z.boolean(),
  shiftType: z.string().nullable(),
  effectiveFrom: z.string().nullable(),
  effectiveUntil: z.string().nullable(),
});

export const WorkPreferenceOutput = z.object({
  maxHoursPerWeek: z.number(),
  preferredShiftType: z.string(),
  availableForOvertime: z.boolean(),
  availableForOnCall: z.boolean(),
  workType: z.string(),
});

export const TimeOffRequestOutput = z.object({
  id: z.string(),
  startDate: z.string(),
  endDate: z.string(),
  reason: z.string().nullable(),
  status: z.enum(['pending', 'approved', 'denied', 'cancelled']),
  reviewNotes: z.string().nullable(),
  createdAt: z.string(),
});

/**
 * Normalises whatever raw status string the DB returns into our 4-value enum.
 * The DB's varchar(20) `status` column has no app-side check constraint, so
 * we defensively map common variants to the contract values used downstream.
 */
export function normalizeTimeOffStatus(
  raw: string,
): 'pending' | 'approved' | 'denied' | 'cancelled' {
  const v = raw.toLowerCase().trim();
  if (v === 'approved' || v === 'accepted') return 'approved';
  if (v === 'denied' || v === 'rejected') return 'denied';
  if (v === 'cancelled' || v === 'canceled') return 'cancelled';
  return 'pending';
}
