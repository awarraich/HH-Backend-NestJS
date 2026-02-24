import { z } from 'zod';
import type { MedicationsService } from '../../../models/patients/medications/medications.service';
import type { MedicationAuditContext } from '../../../models/patients/medications/medications.service';
import { formatMedicationListToText } from './format-medication-list.helper';
import { TOOL_NAMES } from '../../constants/mcp.constants';

const searchMedicationsInputSchema = {
  query: z.string().describe('Search query (e.g. "blood pressure", "evening pills")'),
};

export const searchMedicationsTool = {
  name: TOOL_NAMES.SEARCH_MEDICATIONS,
  description:
    "Semantic search over the patient's medications. Use for finding medications by purpose, time, or condition (e.g. 'blood pressure', 'evening pills').",
  inputSchema: searchMedicationsInputSchema,
};

export function createSearchMedicationsHandler(
  medicationsService: MedicationsService,
  patientId: string,
  auditContext?: MedicationAuditContext,
) {
  return async (args: { query: string }) => {
    const query = (args?.query ?? '').trim();
    const list = await medicationsService.searchByQuery(patientId, query, auditContext);
    const text = formatMedicationListToText(list);
    return {
      content: [{ type: 'text' as const, text }],
    };
  };
}
