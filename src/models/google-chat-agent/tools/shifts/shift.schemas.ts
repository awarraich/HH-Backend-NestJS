import { z } from 'zod';

/** YYYY-MM-DD date string. */
export const DateOnly = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}$/, 'Date must be in YYYY-MM-DD format');

export const DateRangeInput = z.object({
  from: DateOnly.optional().describe('Start date YYYY-MM-DD; defaults to today'),
  to: DateOnly.optional().describe(
    'End date YYYY-MM-DD; defaults to 7 days from today',
  ),
});

export const LocationOutput = z.object({
  department: z.string().nullable(),
  station: z.string().nullable(),
  room: z.string().nullable(),
  bed: z.string().nullable(),
  chair: z.string().nullable(),
});

export const AssignmentOutput = z.object({
  id: z.string(),
  shiftId: z.string(),
  shiftName: z.string().nullable(),
  scheduledDate: z.string(),
  startAt: z.string(),
  endAt: z.string(),
  status: z.string(),
  role: z.string().nullable(),
  location: LocationOutput,
  notes: z.string().nullable(),
});

export const AvailableShiftOutput = z.object({
  id: z.string(),
  name: z.string().nullable(),
  shiftType: z.string().nullable(),
  startAt: z.string(),
  endAt: z.string(),
  recurrenceType: z.string(),
  requiredRoles: z.array(z.string()),
});
