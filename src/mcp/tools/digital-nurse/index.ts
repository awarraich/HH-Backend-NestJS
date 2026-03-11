import type { MedicationsService } from '../../../models/patients/medications/medications.service';
import type { MedicationAuditContext } from '../../../models/patients/medications/medications.service';
import { listMedicationsTool, createListMedicationsHandler } from './list-medications.tool';
import { searchMedicationsTool, createSearchMedicationsHandler } from './search-medications.tool';
import {
  markMedicationTakenTool,
  createMarkMedicationTakenHandler,
} from './mark-medication-taken.tool';

export const digitalNurseTools = [
  listMedicationsTool,
  searchMedicationsTool,
  markMedicationTakenTool,
];

export type McpToolResult = Promise<{ content: Array<{ type: 'text'; text: string }> }>;

export function registerDigitalNurseHandlers(
  medicationsService: MedicationsService,
  patientId: string,
  auditContext?: MedicationAuditContext,
): Array<{
  name: string;
  description: string;
  inputSchema: object;
  handler: (args: unknown) => McpToolResult;
}> {
  return [
    {
      ...listMedicationsTool,
      handler: createListMedicationsHandler(medicationsService, patientId, auditContext),
    },
    {
      ...searchMedicationsTool,
      handler: createSearchMedicationsHandler(medicationsService, patientId, auditContext),
    },
    {
      ...markMedicationTakenTool,
      handler: createMarkMedicationTakenHandler(medicationsService, patientId, auditContext),
    },
  ];
}
