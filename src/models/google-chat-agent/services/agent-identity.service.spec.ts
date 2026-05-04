import { Repository } from 'typeorm';
import { AgentIdentityService } from './agent-identity.service';
import { AGENT_DEFAULT_TIMEZONE } from './agent-identity.types';
import { UserChatConnection } from '../../notifications/entities/user-chat-connection.entity';

type MockRepo = Pick<Repository<UserChatConnection>, 'findOne'>;

const buildService = (
  findOneImpl: MockRepo['findOne'],
): AgentIdentityService => {
  const repo = { findOne: findOneImpl } as unknown as Repository<UserChatConnection>;
  return new AgentIdentityService(repo);
};

const connectedRow = (
  overrides: Partial<UserChatConnection> = {},
): UserChatConnection =>
  ({
    id: 'conn-uuid',
    user_id: 'user-uuid-1',
    org_id: 'org-uuid-1',
    provider: 'google_chat',
    chat_user_id: 'users/123',
    dm_space_name: 'spaces/AAA',
    status: 'connected',
    chat_eligible: true,
    connected_at: new Date(),
    revoked_at: null,
    created_at: new Date(),
    updated_at: new Date(),
    ...overrides,
  }) as UserChatConnection;

describe('AgentIdentityService (M2)', () => {
  // M2-U1: Returns null when no user_chat_connections row exists.
  it('returns null when no connection row exists', async () => {
    const service = buildService(jest.fn().mockResolvedValue(null));
    expect(await service.resolve('users/missing')).toBeNull();
  });

  // M2-U2: Returns null when row exists but status='revoked'.
  // The service does this by including status: 'connected' in the WHERE clause —
  // verify that constraint is being applied.
  it('only queries for status=connected (revoked rows would be excluded)', async () => {
    const findOne = jest.fn().mockResolvedValue(null);
    const service = buildService(findOne);

    await service.resolve('users/abc');

    expect(findOne).toHaveBeenCalledWith({
      where: {
        chat_user_id: 'users/abc',
        provider: 'google_chat',
        status: 'connected',
      },
    });
  });

  it('returns null when status is pending (filter excludes it)', async () => {
    // The repository would not return a non-connected row given the WHERE clause,
    // so a null result here mirrors that path.
    const service = buildService(jest.fn().mockResolvedValue(null));
    expect(await service.resolve('users/pending')).toBeNull();
  });

  // M2-U3: Returns the agent default timezone (UTC) until org/user gain one.
  it('returns the resolved user with the agent default timezone', async () => {
    const row = connectedRow();
    const service = buildService(jest.fn().mockResolvedValue(row));

    const resolved = await service.resolve('users/123');

    expect(resolved).toEqual({
      userId: 'user-uuid-1',
      organizationId: 'org-uuid-1',
      timezone: AGENT_DEFAULT_TIMEZONE,
      chatUserId: 'users/123',
      chatSpaceName: 'spaces/AAA',
    });
  });

  it('falls back to the input chatUserId when the row stored a null chat_user_id', async () => {
    // Edge case from the entity: chat_user_id is nullable. The resolve path
    // prefers the row's stored value, but if null, returns the caller-supplied id.
    const row = connectedRow({ chat_user_id: null });
    const service = buildService(jest.fn().mockResolvedValue(row));

    const resolved = await service.resolve('users/from-input');
    expect(resolved?.chatUserId).toBe('users/from-input');
  });

  it('returns null for an empty chatUserId without hitting the repo', async () => {
    const findOne = jest.fn();
    const service = buildService(findOne);

    expect(await service.resolve('')).toBeNull();
    expect(findOne).not.toHaveBeenCalled();
  });
});
