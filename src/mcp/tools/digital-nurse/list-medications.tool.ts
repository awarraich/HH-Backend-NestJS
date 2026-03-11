import { z } from 'zod';
import type { MedicationsService } from '../../../models/patients/medications/medications.service';
import type { MedicationAuditContext } from '../../../models/patients/medications/medications.service';
import { formatMedicationListToText } from './format-medication-list.helper';
import { TOOL_NAMES } from '../../constants/mcp.constants';

const listMedicationsInputSchema = {
  date: z.string().optional().describe('Date in YYYY-MM-DD format. Defaults to today.'),
};

export const listMedicationsTool = {
  name: TOOL_NAMES.LIST_MEDICATIONS,
  description:
    "List the patient's current medications with today's taken status. Use for 'what meds do I take', 'medication list', 'today's doses'.",
  inputSchema: listMedicationsInputSchema,
};

export type ListMedicationsResult = Promise<{ content: Array<{ type: 'text'; text: string }> }>;

export function createListMedicationsHandler(
  medicationsService: MedicationsService,
  patientId: string,
  auditContext?: MedicationAuditContext,
): (args: { date?: string }) => ListMedicationsResult {
  return async (args: { date?: string }) => {
    const date = args?.date ?? new Date().toISOString().slice(0, 10);
    const list = await medicationsService.findAll(patientId, date, auditContext);
    const text = formatMedicationListToText(list);
    return {
      content: [{ type: 'text' as const, text }],
    };
  };
}
