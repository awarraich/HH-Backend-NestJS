import type { EmployeesService } from '../../../models/employees/services/employees.service';

/**
 * Decorates a list of records that carry an `employee_id` with the employee's
 * display name and email, so the LLM can refer to people by name in
 * user-facing responses instead of leaking raw UUIDs.
 *
 * The original record fields (including `employee_id`) are preserved so the
 * agent can still chain into write tools like `assign_employee_to_shift`.
 */
export async function enrichRecordsWithEmployeeNames<T extends { employee_id: string }>(
  records: T[],
  employeesService: EmployeesService,
  organizationId: string,
): Promise<Array<T & { employee_name: string; employee_email: string | null }>> {
  if (records.length === 0) return [];

  const ids = Array.from(new Set(records.map((r) => r.employee_id)));
  const displayMap = await employeesService.findDisplayInfoByIds(organizationId, ids);

  return records.map((record) => {
    const display = displayMap.get(record.employee_id);
    return {
      ...record,
      employee_name: display?.name ?? 'Unknown employee',
      employee_email: display?.email ?? null,
    };
  });
}
