import { z } from 'zod';
import type { MedicationsService } from '../../../models/patients/medications/medications.service';
import type { MedicationAuditContext } from '../../../models/patients/medications/medications.service';
import { TOOL_NAMES } from '../../constants/mcp.constants';

const markMedicationTakenInputSchema = {
  medicationId: z.string().describe('The medication ID'),
  timeSlot: z.string().describe('Time slot (e.g. 08:00, 20:00)'),
  date: z.string().describe('Date in YYYY-MM-DD format'),
};

export const markMedicationTakenTool = {
  name: TOOL_NAMES.MARK_MEDICATION_TAKEN,
  description:
    "Record that the patient took a medication at a time slot on a given date. Use when the user says they took a dose or to log adherence.",
  inputSchema: markMedicationTakenInputSchema,
};

export function createMarkMedicationTakenHandler(
  medicationsService: MedicationsService,
  patientId: string,
  auditContext?: MedicationAuditContext,
) {
  return async (args: { medicationId: string; timeSlot: string; date: string }) => {
    const { medicationId, timeSlot, date } = args;
    const result = await medicationsService.markAsTaken(
      patientId,
      medicationId,
      { timeSlot, date },
      auditContext,
    );
    const text = `Recorded: ${result.timeSlot} on ${date} – taken.`;
    return {
      content: [{ type: 'text' as const, text }],
    };
  };
}
