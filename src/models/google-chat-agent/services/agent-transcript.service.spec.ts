import { Repository } from 'typeorm';
import { AgentTranscriptService } from './agent-transcript.service';
import { GoogleChatAgentConfigService } from '../../../config/google-chat-agent/config.service';
import { AgentChatTranscript } from '../entities/agent-chat-transcript.entity';

const buildService = (overrides: {
  piiRedaction?: boolean;
  queryImpl?: jest.Mock;
} = {}) => {
  const queryMock = overrides.queryImpl ?? jest.fn().mockResolvedValue([]);
  const repo = {
    query: queryMock,
    find: jest.fn(),
    count: jest.fn(),
  } as unknown as Repository<AgentChatTranscript>;
  const config = {
    piiRedaction: overrides.piiRedaction ?? false,
  } as unknown as GoogleChatAgentConfigService;
  return {
    service: new AgentTranscriptService(repo, config),
    queryMock,
    repo,
  };
};

const baseInput = () => ({
  organizationId: 'org-uuid-1',
  userId: 'user-uuid-1',
  threadName: 'spaces/AAA/threads/T1',
  role: 'user' as const,
  payload: { text: 'hi' },
});

describe('AgentTranscriptService.recordTurn (M11)', () => {
  it('issues an INSERT with caller scope and payload bound as parameters', async () => {
    const { service, queryMock } = buildService();
    await service.recordTurn(baseInput());

    expect(queryMock).toHaveBeenCalledTimes(1);
    const [sql, params] = queryMock.mock.calls[0];
    expect(sql).toMatch(/INSERT INTO agent_chat_transcripts/);
    expect(params[0]).toBe('org-uuid-1');
    expect(params[1]).toBe('user-uuid-1');
    expect(params[2]).toBe('spaces/AAA/threads/T1');
    expect(params[3]).toBe('user');
  });

  it('computes turn_index via MAX(turn_index)+1 in the SQL (subquery present)', async () => {
    const { service, queryMock } = buildService();
    await service.recordTurn(baseInput());

    const [sql] = queryMock.mock.calls[0];
    expect(sql).toMatch(/SELECT MAX\(turn_index\)/);
    expect(sql).toMatch(/FROM agent_chat_transcripts/);
  });

  // M11-U2-style: tokens flow into the columns (verified at the parameter level).
  it('passes tokensIn and tokensOut into the INSERT parameters', async () => {
    const { service, queryMock } = buildService();
    await service.recordTurn({
      ...baseInput(),
      tokensIn: 1234,
      tokensOut: 567,
    });
    const [, params] = queryMock.mock.calls[0];
    // Positional: organizationId, userId, threadName, role, toolName, payload, tokensIn, tokensOut, costUsd, countsAgainstQuota
    expect(params[6]).toBe(1234);
    expect(params[7]).toBe(567);
  });

  // M11-U3: redaction off → raw payload is written.
  it('writes payload verbatim when piiRedaction is OFF', async () => {
    const { service, queryMock } = buildService({ piiRedaction: false });
    await service.recordTurn({
      ...baseInput(),
      payload: { text: 'Email me at foo@bar.com' },
    });
    const [, params] = queryMock.mock.calls[0];
    const writtenPayload = JSON.parse(params[5] as string);
    expect(writtenPayload.text).toBe('Email me at foo@bar.com');
  });

  // M11-U3: redaction on → emails masked before write.
  it('redacts payload when piiRedaction is ON', async () => {
    const { service, queryMock } = buildService({ piiRedaction: true });
    await service.recordTurn({
      ...baseInput(),
      payload: { text: 'Email me at foo@bar.com' },
    });
    const [, params] = queryMock.mock.calls[0];
    const writtenPayload = JSON.parse(params[5] as string);
    expect(writtenPayload.text).toBe('Email me at [redacted-email]');
  });

  // M11-U4: counts_against_quota=false propagates correctly.
  it('passes countsAgainstQuota=false when supplied (e.g. system/error rows)', async () => {
    const { service, queryMock } = buildService();
    await service.recordTurn({
      ...baseInput(),
      role: 'system',
      countsAgainstQuota: false,
    });
    const [, params] = queryMock.mock.calls[0];
    expect(params[9]).toBe(false);
  });

  it('defaults countsAgainstQuota=true when not supplied', async () => {
    const { service, queryMock } = buildService();
    await service.recordTurn(baseInput());
    const [, params] = queryMock.mock.calls[0];
    expect(params[9]).toBe(true);
  });

  // M11-I1 (unit-flavored): a write failure is swallowed, never thrown.
  it('never throws — DB errors are caught and logged', async () => {
    const failing = jest.fn().mockRejectedValue(new Error('connection refused'));
    const { service } = buildService({ queryImpl: failing });

    await expect(service.recordTurn(baseInput())).resolves.toBeUndefined();
    expect(failing).toHaveBeenCalled();
  });

  it('handles tool rows with toolName in column 4', async () => {
    const { service, queryMock } = buildService();
    await service.recordTurn({
      ...baseInput(),
      role: 'tool',
      toolName: 'listMyShifts',
      payload: { ok: true, output: { shifts: [] } },
    });
    const [, params] = queryMock.mock.calls[0];
    expect(params[3]).toBe('tool');
    expect(params[4]).toBe('listMyShifts');
  });
});
