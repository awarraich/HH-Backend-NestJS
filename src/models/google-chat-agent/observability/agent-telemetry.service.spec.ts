import { Logger } from '@nestjs/common';
import {
  AgentTelemetryService,
  TurnSnapshot,
} from './agent-telemetry.service';

describe('AgentTelemetryService (M16)', () => {
  let logSpy: jest.SpyInstance;
  let errorSpy: jest.SpyInstance;
  let service: AgentTelemetryService;

  beforeEach(() => {
    service = new AgentTelemetryService();
    logSpy = jest
      .spyOn(Logger.prototype, 'log')
      .mockImplementation(() => undefined);
    errorSpy = jest
      .spyOn(Logger.prototype, 'error')
      .mockImplementation(() => undefined);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  const baseSnapshot = (
    overrides: Partial<TurnSnapshot> = {},
  ): TurnSnapshot => ({
    turnId: 'turn-1',
    toolsCalled: [],
    tokensIn: 0,
    tokensOut: 0,
    costUsd: 0,
    latencyMs: 0,
    outcome: 'success',
    ...overrides,
  });

  it('startTurn returns a tracker with elapsedMs increasing over time', async () => {
    const tracker = service.startTurn('turn-1');
    expect(tracker.turnId).toBe('turn-1');
    expect(tracker.elapsedMs()).toBeGreaterThanOrEqual(0);
    await new Promise((r) => setTimeout(r, 25));
    expect(tracker.elapsedMs()).toBeGreaterThanOrEqual(20);
  });

  it('emits a single structured log line containing snapshot fields on success', () => {
    service.recordTurn(
      baseSnapshot({
        userId: 'u1',
        organizationId: 'o1',
        provider: 'openai',
        model: 'gpt-4o',
        toolsCalled: ['listMyShifts'],
        tokensIn: 100,
        tokensOut: 50,
        costUsd: 0.001,
        latencyMs: 1234,
      }),
    );
    expect(logSpy).toHaveBeenCalledTimes(1);
    expect(errorSpy).not.toHaveBeenCalled();
    const line = logSpy.mock.calls[0][0] as string;
    const parsed = JSON.parse(line);
    expect(parsed.event).toBe('agent_turn');
    expect(parsed.turnId).toBe('turn-1');
    expect(parsed.userId).toBe('u1');
    expect(parsed.tokensIn).toBe(100);
    expect(parsed.tokensOut).toBe(50);
    expect(parsed.costUsd).toBe(0.001);
    expect(parsed.latencyMs).toBe(1234);
    expect(parsed.toolsCalled).toEqual(['listMyShifts']);
    expect(parsed.outcome).toBe('success');
  });

  // M16-U1: errored turn emits via Logger.error (not .log) and includes the message.
  it('routes error-outcome turns to logger.error with error.message present', () => {
    service.recordTurn(
      baseSnapshot({
        outcome: 'error',
        error: 'something broke',
        latencyMs: 500,
      }),
    );
    expect(errorSpy).toHaveBeenCalledTimes(1);
    expect(logSpy).not.toHaveBeenCalled();
    const parsed = JSON.parse(errorSpy.mock.calls[0][0] as string);
    expect(parsed.outcome).toBe('error');
    expect(parsed.error).toBe('something broke');
    // M16-U2: latency is recorded even on the error path.
    expect(parsed.latencyMs).toBe(500);
  });

  it('costForTurn delegates to computeCostUsd (gpt-4o rates)', () => {
    // 1000 in + 500 out at $2.5/$10 per million → $0.0075
    expect(service.costForTurn('gpt-4o', 1000, 500)).toBeCloseTo(0.0075, 6);
  });

  it('never throws if the snapshot contains a non-serializable value', () => {
    // Cyclic structures should be caught by the try/catch and emitted as a
    // warn rather than crashing the request path.
    const cyclic: Record<string, unknown> = { a: 1 };
    cyclic.self = cyclic;
    expect(() =>
      service.recordTurn({
        ...baseSnapshot(),
        // Cast to allow injecting the cyclic value into the structured log.
        toolsCalled: cyclic as unknown as string[],
      }),
    ).not.toThrow();
  });
});
