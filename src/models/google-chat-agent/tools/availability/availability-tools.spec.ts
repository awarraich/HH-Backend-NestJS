import type { AvailabilityRuleService } from '../../../employees/availability/services/availability-rule.service';
import type { TimeOffRequestService } from '../../../employees/availability/services/time-off-request.service';
import type { WorkPreferenceService } from '../../../employees/availability/services/work-preference.service';
import type { AvailabilityRule } from '../../../employees/availability/entities/availability-rule.entity';
import type { TimeOffRequest } from '../../../employees/availability/entities/time-off-request.entity';
import type { WorkPreference } from '../../../employees/availability/entities/work-preference.entity';
import type { AgentContext } from '../tool.types';

import { buildGetMyAvailabilityTool } from './get-my-availability.tool';
import { buildGetMyTimeOffRequestsTool } from './get-my-time-off-requests.tool';
import { buildSetAvailabilityRuleTool } from './set-availability-rule.tool';
import { buildRequestTimeOffTool } from './request-time-off.tool';
import { buildCancelTimeOffRequestTool } from './cancel-time-off-request.tool';
import { normalizeTimeOffStatus } from './availability.schemas';

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

const fakeRule = (overrides: Partial<AvailabilityRule> = {}): AvailabilityRule =>
  ({
    id: 'rule-1',
    user_id: 'user-uuid-1',
    organization_id: 'org-uuid-1',
    date: null,
    day_of_week: 2, // Tuesday
    start_time: '09:00:00',
    end_time: '17:00:00',
    is_available: true,
    shift_type: null,
    effective_from: null,
    effective_until: null,
    created_at: new Date(),
    updated_at: new Date(),
    user: {} as AvailabilityRule['user'],
    organization: null,
    ...overrides,
  }) as AvailabilityRule;

const fakeTOR = (overrides: Partial<TimeOffRequest> = {}): TimeOffRequest =>
  ({
    id: 'tor-1',
    user_id: 'user-uuid-1',
    organization_id: 'org-uuid-1',
    start_date: '2026-06-01',
    end_date: '2026-06-03',
    reason: 'Family event',
    status: 'pending',
    reviewed_by: null,
    reviewed_at: null,
    review_notes: null,
    created_at: new Date('2026-05-05T10:00:00Z'),
    updated_at: new Date(),
    user: {} as TimeOffRequest['user'],
    organization: null,
    reviewer: null,
    ...overrides,
  }) as TimeOffRequest;

const fakePrefs = (
  overrides: Partial<WorkPreference> = {},
): WorkPreference =>
  ({
    id: 'pref-1',
    user_id: 'user-uuid-1',
    max_hours_per_week: 40,
    preferred_shift_type: 'morning',
    available_for_overtime: false,
    available_for_on_call: false,
    work_type: 'office',
    ...overrides,
  }) as WorkPreference;

const buildFakeRules = (impls: Partial<AvailabilityRuleService> = {}) =>
  ({
    findByUser: impls.findByUser ?? jest.fn().mockResolvedValue([]),
    upsertWeeklyRuleForUser:
      impls.upsertWeeklyRuleForUser ?? jest.fn().mockResolvedValue(fakeRule()),
  }) as unknown as AvailabilityRuleService;

const buildFakePrefs = () =>
  ({
    findOrCreate: jest.fn().mockResolvedValue(fakePrefs()),
  }) as unknown as WorkPreferenceService;

const buildFakeTimeOff = (impls: Partial<TimeOffRequestService> = {}) =>
  ({
    findAll:
      impls.findAll ??
      jest.fn().mockResolvedValue({ data: [], total: 0, page: 1, limit: 20 }),
    create: impls.create ?? jest.fn().mockResolvedValue(fakeTOR()),
    cancel: impls.cancel ?? jest.fn().mockResolvedValue(fakeTOR()),
    findOne: impls.findOne ?? jest.fn().mockResolvedValue(fakeTOR()),
  }) as unknown as TimeOffRequestService;

// ─── helpers ────────────────────────────────────────────────────────────────

describe('normalizeTimeOffStatus (M6)', () => {
  it('maps approved variants', () => {
    expect(normalizeTimeOffStatus('Approved')).toBe('approved');
    expect(normalizeTimeOffStatus('accepted')).toBe('approved');
  });
  it('maps denied variants', () => {
    expect(normalizeTimeOffStatus('denied')).toBe('denied');
    expect(normalizeTimeOffStatus('REJECTED')).toBe('denied');
  });
  it('maps cancelled variants (US + UK spelling)', () => {
    expect(normalizeTimeOffStatus('cancelled')).toBe('cancelled');
    expect(normalizeTimeOffStatus('canceled')).toBe('cancelled');
  });
  it('falls back to pending for unknown / pending', () => {
    expect(normalizeTimeOffStatus('pending')).toBe('pending');
    expect(normalizeTimeOffStatus('whatever')).toBe('pending');
    expect(normalizeTimeOffStatus('')).toBe('pending');
  });
});

// ─── M6 read tools ───────────────────────────────────────────────────────────

describe('getMyAvailability (M6)', () => {
  it('forwards caller userId + organizationId to findByUser', async () => {
    const findByUser = jest.fn().mockResolvedValue([]);
    const tool = buildGetMyAvailabilityTool(
      buildFakeRules({ findByUser }),
      buildFakePrefs(),
    );
    await tool.handler({}, ctx());
    expect(findByUser).toHaveBeenCalledWith('user-uuid-1', 'org-uuid-1');
  });

  // M6-U1: returns active rules and flattens to camelCase output shape
  it('flattens rules into the agent-facing shape', async () => {
    const tool = buildGetMyAvailabilityTool(
      buildFakeRules({
        findByUser: jest
          .fn()
          .mockResolvedValue([
            fakeRule({ day_of_week: 1, start_time: '08:00:00' }),
          ]),
      }),
      buildFakePrefs(),
    );
    const result = await tool.handler({}, ctx());
    expect(result.rules).toHaveLength(1);
    expect(result.rules[0]).toMatchObject({
      dayOfWeek: 1,
      startTime: '08:00:00',
      isAvailable: true,
    });
  });

  it('always includes work preferences (calls findOrCreate even when no rules)', async () => {
    const findOrCreate = jest.fn().mockResolvedValue(fakePrefs({ max_hours_per_week: 32 }));
    const prefs = { findOrCreate } as unknown as WorkPreferenceService;
    const tool = buildGetMyAvailabilityTool(buildFakeRules(), prefs);
    const result = await tool.handler({}, ctx());
    expect(result.workPreferences.maxHoursPerWeek).toBe(32);
    expect(findOrCreate).toHaveBeenCalledWith('user-uuid-1');
  });
});

describe('getMyTimeOffRequests (M6)', () => {
  // M6-U3: scope is forwarded to underlying service (caller-self filter)
  it('passes caller userId and organization filter to findAll', async () => {
    const findAll = jest
      .fn()
      .mockResolvedValue({ data: [], total: 0, page: 1, limit: 20 });
    const tool = buildGetMyTimeOffRequestsTool(buildFakeTimeOff({ findAll }));
    await tool.handler({}, ctx());

    expect(findAll).toHaveBeenCalledTimes(1);
    const [userIdArg, queryArg] = findAll.mock.calls[0];
    expect(userIdArg).toBe('user-uuid-1');
    expect(queryArg.organization_id).toBe('org-uuid-1');
  });

  // M6-U2: status normalization
  it('normalizes raw DB status strings into the contract enum', async () => {
    const tool = buildGetMyTimeOffRequestsTool(
      buildFakeTimeOff({
        findAll: jest.fn().mockResolvedValue({
          data: [
            fakeTOR({ status: 'Approved' }),
            fakeTOR({ id: 'tor-2', status: 'rejected' }),
            fakeTOR({ id: 'tor-3', status: 'canceled' }),
          ],
          total: 3,
          page: 1,
          limit: 20,
        }),
      }),
    );
    const result = await tool.handler({}, ctx());
    expect(result.requests.map((r) => r.status)).toEqual([
      'approved',
      'denied',
      'cancelled',
    ]);
  });

  it('uses caller-supplied status filter when provided', async () => {
    const findAll = jest
      .fn()
      .mockResolvedValue({ data: [], total: 0, page: 1, limit: 20 });
    const tool = buildGetMyTimeOffRequestsTool(buildFakeTimeOff({ findAll }));
    await tool.handler({ status: 'approved' }, ctx());
    expect(findAll.mock.calls[0][1].status).toBe('approved');
  });
});

// ─── M7 write tools ──────────────────────────────────────────────────────────

describe('setAvailabilityRule (M7)', () => {
  // M7-U1: upsert behavior — single rule per (user, day_of_week)
  it('delegates to upsertWeeklyRuleForUser with caller scope', async () => {
    const upsertWeeklyRuleForUser = jest.fn().mockResolvedValue(
      fakeRule({ day_of_week: 4, start_time: '13:00:00', end_time: '21:00:00' }),
    );
    const tool = buildSetAvailabilityRuleTool(
      buildFakeRules({ upsertWeeklyRuleForUser }),
    );
    await tool.handler(
      { dayOfWeek: 4, startTime: '13:00', endTime: '21:00' },
      ctx(),
    );
    expect(upsertWeeklyRuleForUser).toHaveBeenCalledWith(
      'user-uuid-1',
      expect.objectContaining({
        organization_id: 'org-uuid-1',
        day_of_week: 4,
        start_time: '13:00',
        end_time: '21:00',
        is_available: true,
      }),
    );
  });

  it('rejects out-of-range dayOfWeek via Zod input schema', () => {
    const tool = buildSetAvailabilityRuleTool(buildFakeRules());
    expect(
      tool.input.safeParse({
        dayOfWeek: 7,
        startTime: '09:00',
        endTime: '17:00',
      }).success,
    ).toBe(false);
    expect(
      tool.input.safeParse({
        dayOfWeek: -1,
        startTime: '09:00',
        endTime: '17:00',
      }).success,
    ).toBe(false);
  });

  it('rejects malformed time strings via Zod', () => {
    const tool = buildSetAvailabilityRuleTool(buildFakeRules());
    expect(
      tool.input.safeParse({
        dayOfWeek: 2,
        startTime: '9am',
        endTime: '5pm',
      }).success,
    ).toBe(false);
  });

  it('returns the saved rule with a friendly day-name in the message', async () => {
    const tool = buildSetAvailabilityRuleTool(
      buildFakeRules({
        upsertWeeklyRuleForUser: jest
          .fn()
          .mockResolvedValue(fakeRule({ day_of_week: 2 })),
      }),
    );
    const result = await tool.handler(
      { dayOfWeek: 2, startTime: '09:00', endTime: '17:00' },
      ctx(),
    );
    expect(result.message).toMatch(/Tuesday/i);
  });

  it('reports unavailability differently in the message', async () => {
    const tool = buildSetAvailabilityRuleTool(
      buildFakeRules({
        upsertWeeklyRuleForUser: jest
          .fn()
          .mockResolvedValue(fakeRule({ is_available: false })),
      }),
    );
    const result = await tool.handler(
      {
        dayOfWeek: 2,
        startTime: '09:00',
        endTime: '17:00',
        isAvailable: false,
      },
      ctx(),
    );
    expect(result.message).toMatch(/unavailable/i);
  });

  // REGRESSION: real Chat dev test produced "every Monday" with NO end date
  // because the tool didn't pass effectiveUntil through. User asked
  // "until June 5", got an open-ended Monday rule. This test fails fast if
  // the tool ever stops forwarding the bounds.
  it('forwards effectiveUntil to the service when supplied (regression: until-date dropped)', async () => {
    const upsertWeeklyRuleForUser = jest.fn().mockResolvedValue(
      fakeRule({
        day_of_week: 1,
        effective_until: new Date('2026-06-05'),
      }),
    );
    const tool = buildSetAvailabilityRuleTool(
      buildFakeRules({ upsertWeeklyRuleForUser }),
    );

    await tool.handler(
      {
        dayOfWeek: 1,
        startTime: '07:00',
        endTime: '15:00',
        effectiveUntil: '2026-06-05',
      },
      ctx(),
    );

    expect(upsertWeeklyRuleForUser).toHaveBeenCalledWith(
      'user-uuid-1',
      expect.objectContaining({
        day_of_week: 1,
        effective_until: '2026-06-05',
        // Open-ended start when only the end is bounded.
        effective_from: null,
      }),
    );
  });

  it('forwards both effectiveFrom and effectiveUntil', async () => {
    const upsertWeeklyRuleForUser = jest.fn().mockResolvedValue(fakeRule());
    const tool = buildSetAvailabilityRuleTool(
      buildFakeRules({ upsertWeeklyRuleForUser }),
    );

    await tool.handler(
      {
        dayOfWeek: 3,
        startTime: '08:00',
        endTime: '16:00',
        effectiveFrom: '2026-05-15',
        effectiveUntil: '2026-07-15',
      },
      ctx(),
    );

    expect(upsertWeeklyRuleForUser).toHaveBeenCalledWith(
      'user-uuid-1',
      expect.objectContaining({
        effective_from: '2026-05-15',
        effective_until: '2026-07-15',
      }),
    );
  });

  it('echoes the date range in the success message so the user can verify', async () => {
    const tool = buildSetAvailabilityRuleTool(
      buildFakeRules({
        upsertWeeklyRuleForUser: jest.fn().mockResolvedValue(
          fakeRule({
            day_of_week: 1,
            effective_until: new Date('2026-06-05'),
          }),
        ),
      }),
    );

    const result = await tool.handler(
      {
        dayOfWeek: 1,
        startTime: '07:00',
        endTime: '15:00',
        effectiveUntil: '2026-06-05',
      },
      ctx(),
    );

    expect(result.message).toMatch(/until 2026-06-05/);
  });

  it('rejects malformed effectiveUntil via Zod', () => {
    const tool = buildSetAvailabilityRuleTool(buildFakeRules());
    expect(
      tool.input.safeParse({
        dayOfWeek: 1,
        startTime: '07:00',
        endTime: '15:00',
        effectiveUntil: 'June 5',
      }).success,
    ).toBe(false);
  });
});

describe('requestTimeOff (M7)', () => {
  // M7-U2: backdated requests rejected
  it('rejects backdated startDate', async () => {
    const tool = buildRequestTimeOffTool(buildFakeTimeOff());
    await expect(
      tool.handler(
        { startDate: '2020-01-01', endDate: '2020-01-02' },
        ctx(),
      ),
    ).rejects.toThrow(/already passed/i);
  });

  it('rejects endDate before startDate', async () => {
    const tool = buildRequestTimeOffTool(buildFakeTimeOff());
    await expect(
      tool.handler(
        { startDate: '2099-12-10', endDate: '2099-12-05' },
        ctx(),
      ),
    ).rejects.toThrow(/endDate must be on or after/i);
  });

  it('creates a new pending request when no duplicate exists', async () => {
    const create = jest.fn().mockResolvedValue(
      fakeTOR({ start_date: '2099-12-10', end_date: '2099-12-12' }),
    );
    const tool = buildRequestTimeOffTool(
      buildFakeTimeOff({
        findAll: jest
          .fn()
          .mockResolvedValue({ data: [], total: 0, page: 1, limit: 50 }),
        create,
      }),
    );
    const result = await tool.handler(
      { startDate: '2099-12-10', endDate: '2099-12-12', reason: 'Trip' },
      ctx(),
    );
    expect(create).toHaveBeenCalledWith(
      'user-uuid-1',
      expect.objectContaining({
        organization_id: 'org-uuid-1',
        start_date: '2099-12-10',
        end_date: '2099-12-12',
        reason: 'Trip',
      }),
    );
    expect(result.message).toMatch(/submitted/i);
  });

  // Idempotency-lite: duplicate pending request → return existing, do not create
  it('does NOT create a duplicate when a pending request with same window exists', async () => {
    const existing = fakeTOR({
      id: 'tor-existing',
      start_date: '2099-12-10',
      end_date: '2099-12-12',
      reason: 'Trip',
    });
    const create = jest.fn();
    const tool = buildRequestTimeOffTool(
      buildFakeTimeOff({
        findAll: jest.fn().mockResolvedValue({
          data: [existing],
          total: 1,
          page: 1,
          limit: 50,
        }),
        create,
      }),
    );
    const result = await tool.handler(
      { startDate: '2099-12-10', endDate: '2099-12-12', reason: 'Trip' },
      ctx(),
    );
    expect(create).not.toHaveBeenCalled();
    expect(result.request.id).toBe('tor-existing');
    expect(result.message).toMatch(/already have a pending/i);
  });
});

describe('cancelTimeOffRequest (M7)', () => {
  it('passes caller userId and request id to service.cancel', async () => {
    const cancel = jest
      .fn()
      .mockResolvedValue(fakeTOR({ id: 'tor-9' }));
    const tool = buildCancelTimeOffRequestTool(
      buildFakeTimeOff({ cancel }),
    );
    await tool.handler(
      { requestId: '00000000-0000-0000-0000-000000000009' },
      ctx(),
    );
    expect(cancel).toHaveBeenCalledWith(
      'user-uuid-1',
      '00000000-0000-0000-0000-000000000009',
    );
  });

  // M7-U4: only-pending check is enforced at the service layer; we propagate
  it('propagates the service\'s only-pending error when cancel throws', async () => {
    const cancel = jest
      .fn()
      .mockRejectedValue(new Error('Only pending requests can be cancelled'));
    const tool = buildCancelTimeOffRequestTool(
      buildFakeTimeOff({ cancel }),
    );
    await expect(
      tool.handler(
        { requestId: '00000000-0000-0000-0000-000000000001' },
        ctx(),
      ),
    ).rejects.toThrow(/Only pending/);
  });

  // M7-U3: cancelling another user's request → service throws NotFound
  it('propagates NotFound when the request does not belong to the caller', async () => {
    const cancel = jest
      .fn()
      .mockRejectedValue(new Error('Time-off request not found'));
    const tool = buildCancelTimeOffRequestTool(
      buildFakeTimeOff({ cancel }),
    );
    await expect(
      tool.handler(
        { requestId: '00000000-0000-0000-0000-000000000002' },
        ctx(),
      ),
    ).rejects.toThrow(/not found/i);
  });

  it('rejects malformed requestId via Zod', () => {
    const tool = buildCancelTimeOffRequestTool(buildFakeTimeOff());
    expect(tool.input.safeParse({ requestId: 'not-a-uuid' }).success).toBe(
      false,
    );
  });
});

describe('Tool registration shape', () => {
  it('all five availability tools have unique, expected names', () => {
    const tools = [
      buildGetMyAvailabilityTool(buildFakeRules(), buildFakePrefs()),
      buildGetMyTimeOffRequestsTool(buildFakeTimeOff()),
      buildSetAvailabilityRuleTool(buildFakeRules()),
      buildRequestTimeOffTool(buildFakeTimeOff()),
      buildCancelTimeOffRequestTool(buildFakeTimeOff()),
    ];
    const names = tools.map((t) => t.name);
    expect(new Set(names).size).toBe(names.length);
    expect(names).toEqual([
      'getMyAvailability',
      'getMyTimeOffRequests',
      'setAvailabilityRule',
      'requestTimeOff',
      'cancelTimeOffRequest',
    ]);
  });
});
