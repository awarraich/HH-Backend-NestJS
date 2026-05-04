import type { EmployeeShiftService } from '../../../organizations/scheduling/services/employee-shift.service';
import type { EmployeeShift } from '../../../organizations/scheduling/entities/employee-shift.entity';
import type { Shift } from '../../../organizations/scheduling/entities/shift.entity';
import { buildListMyShiftsTool } from './list-my-shifts.tool';
import { buildGetShiftDetailsTool } from './get-shift-details.tool';
import { buildListAvailableShiftsTool } from './list-available-shifts.tool';
import type { AgentContext } from '../tool.types';
import { defaultShiftRange } from './date-range';

const ctx = (
  overrides: Partial<AgentContext['user']> = {},
): AgentContext => ({
  user: {
    userId: 'user-uuid-1',
    organizationId: 'org-uuid-1',
    timezone: 'UTC',
    chatUserId: 'users/123',
    chatSpaceName: 'spaces/AAA',
    ...overrides,
  },
  turnId: 'turn-1',
});

const fakeShift = (overrides: Partial<Shift> = {}): Shift =>
  ({
    id: 'shift-1',
    organization_id: 'org-uuid-1',
    start_at: new Date('2026-05-10T08:00:00Z'),
    end_at: new Date('2026-05-10T16:00:00Z'),
    name: 'Morning Shift',
    shift_type: 'DAY',
    status: 'ACTIVE',
    recurrence_type: 'ONE_TIME',
    recurrence_days: null,
    recurrence_start_date: null,
    recurrence_end_date: null,
    created_at: new Date(),
    updated_at: new Date(),
    organization: {} as Shift['organization'],
    employeeShifts: [],
    shiftRoles: [],
    departmentShifts: [],
    ...overrides,
  }) as Shift;

const fakeAssignment = (
  overrides: Partial<EmployeeShift> = {},
): EmployeeShift =>
  ({
    id: 'es-1',
    shift_id: 'shift-1',
    employee_id: 'emp-uuid-1',
    scheduled_date: '2026-05-10',
    department_id: null,
    station_id: null,
    room_id: null,
    bed_id: null,
    chair_id: null,
    status: 'SCHEDULED',
    role: 'NURSE',
    notes: null,
    actual_start_at: null,
    actual_end_at: null,
    created_at: new Date(),
    updated_at: new Date(),
    shift: fakeShift(),
    employee: {} as EmployeeShift['employee'],
    department: null,
    station: null,
    room: null,
    bed: null,
    chair: null,
    ...overrides,
  }) as EmployeeShift;

const buildFakeService = (
  impls: Partial<{
    findByCallerSelf: EmployeeShiftService['findByCallerSelf'];
    findShiftDetailsForCallerSelf: EmployeeShiftService['findShiftDetailsForCallerSelf'];
    findAvailableForCallerSelf: EmployeeShiftService['findAvailableForCallerSelf'];
  }> = {},
): EmployeeShiftService =>
  ({
    findByCallerSelf:
      impls.findByCallerSelf ?? jest.fn().mockResolvedValue([]),
    findShiftDetailsForCallerSelf:
      impls.findShiftDetailsForCallerSelf ??
      jest.fn().mockResolvedValue(null),
    findAvailableForCallerSelf:
      impls.findAvailableForCallerSelf ??
      jest.fn().mockResolvedValue([]),
  }) as unknown as EmployeeShiftService;

describe('listMyShifts (M5)', () => {
  // M5-U1: filters strictly to caller's employee_id (delegates to service which scopes by user)
  it('passes caller userId + organizationId to the service', async () => {
    const findByCallerSelf = jest.fn().mockResolvedValue([]);
    const tool = buildListMyShiftsTool(buildFakeService({ findByCallerSelf }));

    await tool.handler({}, ctx());

    expect(findByCallerSelf).toHaveBeenCalledWith(
      'org-uuid-1',
      'user-uuid-1',
      expect.any(Object),
    );
  });

  // M5-U2: defaults to today→+7d when no range given.
  it('defaults to today through +7 days when from/to are absent', async () => {
    const findByCallerSelf = jest.fn().mockResolvedValue([]);
    const tool = buildListMyShiftsTool(buildFakeService({ findByCallerSelf }));

    const result = await tool.handler({}, ctx());

    expect(result.range.from).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    expect(result.range.to).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    const expected = defaultShiftRange();
    expect(result.range).toEqual(expected);
  });

  it('honors caller-supplied from/to', async () => {
    const findByCallerSelf = jest.fn().mockResolvedValue([]);
    const tool = buildListMyShiftsTool(buildFakeService({ findByCallerSelf }));

    await tool.handler({ from: '2026-06-01', to: '2026-06-30' }, ctx());

    expect(findByCallerSelf).toHaveBeenCalledWith(
      'org-uuid-1',
      'user-uuid-1',
      { from: '2026-06-01', to: '2026-06-30' },
    );
  });

  it('flattens employee_shift rows into the assignment output shape', async () => {
    const tool = buildListMyShiftsTool(
      buildFakeService({
        findByCallerSelf: jest
          .fn()
          .mockResolvedValue([
            fakeAssignment({
              id: 'es-1',
              role: 'NURSE',
              status: 'SCHEDULED',
              scheduled_date: '2026-05-10',
            }),
          ]),
      }),
    );

    const result = await tool.handler({}, ctx());
    expect(result.shifts).toHaveLength(1);
    expect(result.shifts[0]).toMatchObject({
      id: 'es-1',
      shiftId: 'shift-1',
      shiftName: 'Morning Shift',
      scheduledDate: '2026-05-10',
      status: 'SCHEDULED',
      role: 'NURSE',
    });
  });

  it('returns empty list when caller has no Employee record (service returns [])', async () => {
    const tool = buildListMyShiftsTool(
      buildFakeService({ findByCallerSelf: jest.fn().mockResolvedValue([]) }),
    );
    const result = await tool.handler({}, ctx());
    expect(result.shifts).toEqual([]);
  });

  it('rejects malformed dates via Zod input schema', () => {
    const tool = buildListMyShiftsTool(buildFakeService());
    const parsed = tool.input.safeParse({ from: 'not-a-date' });
    expect(parsed.success).toBe(false);
  });
});

describe('getShiftDetails (M5)', () => {
  it('returns found=false when caller is not assigned to the shift', async () => {
    const tool = buildGetShiftDetailsTool(
      buildFakeService({
        findShiftDetailsForCallerSelf: jest.fn().mockResolvedValue(null),
      }),
    );
    const result = await tool.handler(
      { shiftId: '00000000-0000-0000-0000-000000000001' },
      ctx(),
    );
    expect(result.found).toBe(false);
    expect(result.message).toMatch(/not assigned/i);
    expect(result.shift).toBeUndefined();
    expect(result.myAssignments).toBeUndefined();
  });

  // M5-U3: returns shift + ONLY the caller's assignments (service guarantees scope)
  it('returns the shift and the caller\'s own assignments when found', async () => {
    const tool = buildGetShiftDetailsTool(
      buildFakeService({
        findShiftDetailsForCallerSelf: jest.fn().mockResolvedValue({
          shift: fakeShift({ id: 'shift-9', name: 'NOC' }),
          assignments: [
            fakeAssignment({
              id: 'es-9',
              shift_id: 'shift-9',
              scheduled_date: '2026-05-15',
            }),
          ],
        }),
      }),
    );
    const result = await tool.handler(
      { shiftId: '00000000-0000-0000-0000-000000000009' },
      ctx(),
    );
    expect(result.found).toBe(true);
    expect(result.shift?.id).toBe('shift-9');
    expect(result.shift?.name).toBe('NOC');
    expect(result.myAssignments).toHaveLength(1);
    expect(result.myAssignments?.[0].id).toBe('es-9');
  });

  it('forwards organizationId and userId from context to the service', async () => {
    const findShiftDetailsForCallerSelf = jest.fn().mockResolvedValue(null);
    const tool = buildGetShiftDetailsTool(
      buildFakeService({ findShiftDetailsForCallerSelf }),
    );
    await tool.handler(
      { shiftId: '00000000-0000-0000-0000-000000000001' },
      ctx({ organizationId: 'org-Z', userId: 'user-Z' }),
    );
    expect(findShiftDetailsForCallerSelf).toHaveBeenCalledWith(
      'org-Z',
      'user-Z',
      '00000000-0000-0000-0000-000000000001',
    );
  });

  it('rejects non-uuid shiftId via Zod input schema', () => {
    const tool = buildGetShiftDetailsTool(buildFakeService());
    expect(tool.input.safeParse({ shiftId: 'not-a-uuid' }).success).toBe(false);
  });
});

describe('listAvailableShifts (M5)', () => {
  // M5-U4: includes the "talk to your manager" note (informational, never self-assigns)
  it('always includes a manager-mediated note in the output', async () => {
    const tool = buildListAvailableShiftsTool(
      buildFakeService({
        findAvailableForCallerSelf: jest.fn().mockResolvedValue([]),
      }),
    );
    const result = await tool.handler({}, ctx());
    expect(result.note).toMatch(/manager/i);
  });

  it('flattens shifts into the available-shift output shape', async () => {
    const tool = buildListAvailableShiftsTool(
      buildFakeService({
        findAvailableForCallerSelf: jest
          .fn()
          .mockResolvedValue([
            fakeShift({
              id: 'shift-x',
              name: 'Late shift',
              shift_type: 'EVENING',
              recurrence_type: 'WEEKDAYS',
            }),
          ]),
      }),
    );
    const result = await tool.handler({}, ctx());
    expect(result.shifts).toHaveLength(1);
    expect(result.shifts[0]).toMatchObject({
      id: 'shift-x',
      name: 'Late shift',
      shiftType: 'EVENING',
      recurrenceType: 'WEEKDAYS',
    });
  });

  it('forwards caller scope to the service', async () => {
    const findAvailableForCallerSelf = jest.fn().mockResolvedValue([]);
    const tool = buildListAvailableShiftsTool(
      buildFakeService({ findAvailableForCallerSelf }),
    );
    await tool.handler({}, ctx({ organizationId: 'org-B', userId: 'user-B' }));
    expect(findAvailableForCallerSelf).toHaveBeenCalledWith(
      'org-B',
      'user-B',
      expect.any(Object),
    );
  });
});

describe('Shift tool registry shapes', () => {
  it('all three tools have unique names', () => {
    const tools = [
      buildListMyShiftsTool(buildFakeService()),
      buildGetShiftDetailsTool(buildFakeService()),
      buildListAvailableShiftsTool(buildFakeService()),
    ];
    const names = tools.map((t) => t.name);
    expect(new Set(names).size).toBe(names.length);
    expect(names).toEqual([
      'listMyShifts',
      'getShiftDetails',
      'listAvailableShifts',
    ]);
  });
});
