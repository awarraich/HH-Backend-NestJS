import type { AvailabilityRuleService } from '../../../employees/availability/services/availability-rule.service';
import type { AvailabilityRule } from '../../../employees/availability/entities/availability-rule.entity';
import type { AgentContext } from '../tool.types';
import { buildSetAvailabilityForDateTool } from './set-availability-for-date.tool';

const ctx = (): AgentContext => ({
  user: {
    userId: 'user-uuid-1',
    organizationId: 'org-uuid-1',
    timezone: 'UTC',
    chatUserId: 'users/123',
    chatSpaceName: 'spaces/AAA',
  },
  turnId: 'turn-1',
});

const fakeRule = (
  overrides: Partial<AvailabilityRule> = {},
): AvailabilityRule =>
  ({
    id: 'rule-1',
    user_id: 'user-uuid-1',
    organization_id: 'org-uuid-1',
    date: '2099-12-31',
    day_of_week: 4,
    start_time: '07:00:00',
    end_time: '15:00:00',
    is_available: true,
    shift_type: null,
    effective_from: new Date('2099-12-31'),
    effective_until: new Date('2099-12-31'),
    created_at: new Date(),
    updated_at: new Date(),
    user: {} as AvailabilityRule['user'],
    organization: null,
    ...overrides,
  }) as AvailabilityRule;

const buildFakeService = (
  upsertImpl?: AvailabilityRuleService['upsertDateOverride'],
): AvailabilityRuleService =>
  ({
    upsertDateOverride: upsertImpl ?? jest.fn().mockResolvedValue([fakeRule()]),
  }) as unknown as AvailabilityRuleService;

const FUTURE = '2099-12-31';

describe('setAvailabilityForDate (M7 — date-specific override)', () => {
  it('delegates to upsertDateOverride with the caller scope', async () => {
    const upsert = jest.fn().mockResolvedValue([fakeRule()]);
    const tool = buildSetAvailabilityForDateTool(buildFakeService(upsert));

    await tool.handler(
      { date: FUTURE, startTime: '07:00', endTime: '15:00' },
      ctx(),
    );

    expect(upsert).toHaveBeenCalledTimes(1);
    const [userId, date, dto] = upsert.mock.calls[0];
    expect(userId).toBe('user-uuid-1');
    expect(date).toBe(FUTURE);
    expect(dto).toMatchObject({
      organization_id: 'org-uuid-1',
      rules: [
        expect.objectContaining({
          start_time: '07:00',
          end_time: '15:00',
          is_available: true,
        }),
      ],
    });
  });

  it('rejects backdated dates without calling the service', async () => {
    const upsert = jest.fn();
    const tool = buildSetAvailabilityForDateTool(buildFakeService(upsert));

    await expect(
      tool.handler(
        { date: '2020-01-01', startTime: '07:00', endTime: '15:00' },
        ctx(),
      ),
    ).rejects.toThrow(/already passed/i);

    expect(upsert).not.toHaveBeenCalled();
  });

  it('rejects equal start and end times', async () => {
    const tool = buildSetAvailabilityForDateTool(buildFakeService());
    await expect(
      tool.handler(
        { date: FUTURE, startTime: '08:00', endTime: '08:00' },
        ctx(),
      ),
    ).rejects.toThrow(/cannot be equal/i);
  });

  it('rejects malformed dates via Zod input schema', () => {
    const tool = buildSetAvailabilityForDateTool(buildFakeService());
    expect(
      tool.input.safeParse({
        date: 'not-a-date',
        startTime: '07:00',
        endTime: '15:00',
      }).success,
    ).toBe(false);
  });

  it('returns flattened rule output and a friendly success message', async () => {
    const tool = buildSetAvailabilityForDateTool(
      buildFakeService(
        jest.fn().mockResolvedValue([
          fakeRule({
            date: FUTURE,
            day_of_week: 4,
            start_time: '07:00:00',
            end_time: '15:00:00',
          }),
        ]),
      ),
    );

    const result = await tool.handler(
      { date: FUTURE, startTime: '07:00', endTime: '15:00' },
      ctx(),
    );

    expect(result.rule.date).toBe(FUTURE);
    expect(result.rule.startTime).toBe('07:00:00');
    expect(result.rule.dayOfWeek).toBe(4);
    expect(result.message).toContain(FUTURE);
    expect(result.message).toMatch(/available/i);
  });

  it('sends shift_type as undefined (not null) so it satisfies the DTO type', async () => {
    const upsert = jest.fn().mockResolvedValue([fakeRule()]);
    const tool = buildSetAvailabilityForDateTool(buildFakeService(upsert));

    await tool.handler(
      { date: FUTURE, startTime: '07:00', endTime: '15:00' },
      ctx(),
    );

    const passedRule = upsert.mock.calls[0][2].rules[0];
    // null isn't allowed by the DTO; we coerce to undefined.
    expect(passedRule.shift_type).toBeUndefined();
  });

  it('throws when the underlying service returns no rule (defensive)', async () => {
    const tool = buildSetAvailabilityForDateTool(
      buildFakeService(jest.fn().mockResolvedValue([])),
    );

    await expect(
      tool.handler(
        { date: FUTURE, startTime: '07:00', endTime: '15:00' },
        ctx(),
      ),
    ).rejects.toThrow(/not saved/i);
  });
});
