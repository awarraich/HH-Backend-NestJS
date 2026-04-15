import type { EmployeeShiftService } from '../../../models/organizations/scheduling/services/employee-shift.service';

export interface AssignmentSummary {
  shift_id: string;
  shift_name: string | null;
  scheduled_date: string;
  status: string;
}

/**
 * Attaches real `employee_shifts` rows to availability records so the LLM
 * sees actual bookings (not just availability rules) when answering
 * "is this employee assigned?". Without this, the AI conflates "has
 * availability rule" with "already assigned" and misreports status.
 */
export async function enrichRecordsWithAssignments<T extends { employee_id: string }>(
  records: T[],
  employeeShiftService: EmployeeShiftService,
  organizationId: string,
): Promise<Array<T & { current_assignments: AssignmentSummary[] }>> {
  if (records.length === 0) return [];

  const ids = Array.from(new Set(records.map((r) => r.employee_id)));
  const rows = await employeeShiftService.findAssignmentsForEmployees(organizationId, ids);

  const byEmployee = new Map<string, AssignmentSummary[]>();
  for (const row of rows) {
    const list = byEmployee.get(row.employee_id) ?? [];
    list.push({
      shift_id: row.shift_id,
      shift_name: row.shift_name,
      scheduled_date: row.scheduled_date,
      status: row.status,
    });
    byEmployee.set(row.employee_id, list);
  }

  return records.map((record) => ({
    ...record,
    current_assignments: byEmployee.get(record.employee_id) ?? [],
  }));
}
