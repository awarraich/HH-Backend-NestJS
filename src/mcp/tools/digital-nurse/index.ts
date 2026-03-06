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

export function registerDigitalNurseHandlers(
  medicationsService: MedicationsService,
  patientId: string,
  auditContext?: MedicationAuditContext,
) {
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
