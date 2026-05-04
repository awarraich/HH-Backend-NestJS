import { Injectable, Logger, BadRequestException, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { In, Repository } from 'typeorm';
import { User } from '../../../authentication/entities/user.entity';
import { OrganizationStaff } from '../../organizations/staff-management/entities/organization-staff.entity';
import { Organization } from '../../organizations/entities/organization.entity';
import { Employee } from '../../employees/entities/employee.entity';
import { OrganizationIntegration } from '../entities/organization-integration.entity';
import { UserChatConnection } from '../entities/user-chat-connection.entity';
import { GoogleChatConfigService } from '../../../config/google-chat/config.service';
import { GoogleChatChannelService } from './channels/google-chat-channel.service';

export type EmployeeOrgIntegrationStatus = 'active' | 'pending' | 'disabled' | 'not_enabled';
export type ChatConnectionTier = 'deep_link' | 'zero_click';

export interface EmployeeNotificationStatus {
  email_destination: string;
  org_integration_status: EmployeeOrgIntegrationStatus;
  workspace_domain: string | null;
  chat_connection: {
    status: 'connected' | 'revoked' | 'pending';
    chat_eligible: boolean;
    connected_at: Date | null;
  } | null;
}

export interface ConnectChatResult {
  tier: ChatConnectionTier;
  url?: string;
  connection?: EmployeeNotificationStatus['chat_connection'];
}

@Injectable()
export class EmployeeNotificationsService {
  private readonly logger = new Logger(EmployeeNotificationsService.name);

  constructor(
    @InjectRepository(User) private readonly users: Repository<User>,
    @InjectRepository(OrganizationStaff)
    private readonly orgStaff: Repository<OrganizationStaff>,
    @InjectRepository(Organization)
    private readonly orgs: Repository<Organization>,
    @InjectRepository(Employee)
    private readonly employees: Repository<Employee>,
    @InjectRepository(OrganizationIntegration)
    private readonly orgIntegrations: Repository<OrganizationIntegration>,
    @InjectRepository(UserChatConnection)
    private readonly connections: Repository<UserChatConnection>,
    private readonly chatConfig: GoogleChatConfigService,
    private readonly chatChannel: GoogleChatChannelService,
  ) {}

  async getStatus(userId: string): Promise<EmployeeNotificationStatus> {
    const user = await this.users.findOne({ where: { id: userId } });
    if (!user) throw new NotFoundException('User not found');

    const integration = await this.findUsersOrgIntegration(userId);
    const connection = await this.connections.findOne({
      where: { user_id: userId, provider: 'google_chat' },
    });

    return {
      email_destination: user.email,
      org_integration_status: this.mapIntegrationStatus(integration),
      workspace_domain: integration?.workspace_domain ?? null,
      chat_connection: connection
        ? {
            status: connection.status,
            chat_eligible: connection.chat_eligible,
            connected_at: connection.connected_at,
          }
        : null,
    };
  }

  async connectChat(userId: string): Promise<ConnectChatResult> {
    const user = await this.users.findOne({ where: { id: userId } });
    if (!user) throw new NotFoundException('User not found');

    const integration = await this.findUsersOrgIntegration(userId);
    if (!integration || integration.status !== 'active') {
      throw new BadRequestException(
        "Your organization hasn't enabled Google Chat reminders yet. Ask your admin to enable it in Settings.",
      );
    }

    const userDomain = (user.email.split('@')[1] ?? '').toLowerCase();
    const workspaceDomain = integration.workspace_domain?.toLowerCase() ?? null;
    const allowsPersonal = (integration.config as { allow_personal_accounts?: boolean } | null)
      ?.allow_personal_accounts;

    if (workspaceDomain && userDomain !== workspaceDomain && !allowsPersonal) {
      throw new BadRequestException(
        `Chat reminders are only available for accounts on your organization's Google Workspace (${integration.workspace_domain}). You'll continue to receive reminders by email.`,
      );
    }

    const installationMode =
      (integration.config as { installation_mode?: 'whitelist' | 'domain' } | null)
        ?.installation_mode ?? 'whitelist';

    if (installationMode === 'domain') {
      // Tier 3 (zero-click) — post-Marketplace + admin domain-installed.
      // Implementation deferred: needs chat.spaces.findDirectMessage + spaces.messages.create
      // to provision the connection server-side. For v1 we fall through to Tier 2.
    }

    const appId = this.chatConfig.appId;
    if (!appId) {
      throw new BadRequestException(
        'Chat app ID not configured on the server. Contact your HomeHealth administrator.',
      );
    }

    return {
      tier: 'deep_link',
      url: `https://chat.google.com/u/0/app/${appId}`,
    };
  }

  async disconnectChat(userId: string): Promise<{ connection: EmployeeNotificationStatus['chat_connection'] }> {
    const connection = await this.connections.findOne({
      where: { user_id: userId, provider: 'google_chat' },
    });
    if (!connection) {
      throw new NotFoundException('No Chat connection to disconnect.');
    }

    // Best-effort: tell the bot to leave the user's Chat space so the bot
    // disappears from their conversation list. Don't fail the disconnect if
    // the API call errors — the user clicked disconnect, our DB should
    // reflect that regardless.
    //
    // **Known Google limitation pre-Marketplace:** for 1:1 DM spaces (which
    // is all our reminders use), `chat.spaces.members.delete` is gated by
    // "administrator approval" — i.e. the Chat app must be Marketplace-
    // published AND a Workspace admin must domain-install it. Pre-Marketplace
    // Google rejects with "DMs are not supported for methods requiring app
    // authentication with administrator approval." Once module 18 ships and
    // the customer's admin domain-installs the bot, this starts working.
    // Until then, we expect this failure and tell the user to remove the bot
    // manually in Chat after disconnect.
    if (connection.dm_space_name) {
      try {
        await this.chatChannel.leaveSpace(connection.dm_space_name);
      } catch (err) {
        const msg = (err as Error).message;
        const isExpectedPreMarketplaceLimitation =
          msg.includes('DMs are not supported') ||
          msg.includes('insufficient authentication scopes');
        if (isExpectedPreMarketplaceLimitation) {
          this.logger.log(
            `leaveSpace skipped for ${connection.dm_space_name} — Google blocks this on DMs pre-Marketplace; user will need to remove the bot manually`,
          );
        } else {
          this.logger.warn(
            `leaveSpace failed for user ${userId} (${connection.dm_space_name}); proceeding with DB-only disconnect: ${msg}`,
          );
        }
      }
    }

    connection.status = 'revoked';
    connection.revoked_at = new Date();
    await this.connections.save(connection);

    return {
      connection: {
        status: connection.status,
        chat_eligible: connection.chat_eligible,
        connected_at: connection.connected_at,
      },
    };
  }

  /**
   * Resolves the user's org membership by union of three signals:
   *   1. Owner — `organizations.user_id` matches the actor.
   *   2. Staff — `organization_staff` row with status='ACTIVE'.
   *   3. Employee — `employees` row with status='ACTIVE' (or 'active').
   *
   * A HomeHealth user can hold any combination of these roles in one or more
   * orgs. We union the org_ids and pick the first one with an active Chat
   * integration. Cross-tenant employees (multiple matching orgs) is open
   * design question #1 — for v1 we pick the first match deterministically.
   */
  private async findUsersOrgIntegration(userId: string): Promise<OrganizationIntegration | null> {
    const [ownerOrgs, staffRows, employeeRows] = await Promise.all([
      this.orgs.find({ where: { user_id: userId } }),
      this.orgStaff.find({ where: { user_id: userId, status: 'ACTIVE' } }),
      this.employees.find({ where: { user_id: userId, status: In(['ACTIVE', 'active']) } }),
    ]);

    const orgIds = new Set<string>([
      ...ownerOrgs.map((o) => o.id),
      ...staffRows.map((s) => s.organization_id),
      ...employeeRows
        .map((e) => e.organization_id)
        .filter((id): id is string => Boolean(id)),
    ]);

    if (orgIds.size === 0) return null;

    const integrations = await this.orgIntegrations.find({
      where: { provider: 'google_chat', org_id: In([...orgIds]) },
    });

    const active = integrations.find((i) => i.status === 'active');
    if (active) return active;
    return integrations[0] ?? null;
  }

  private mapIntegrationStatus(
    integration: OrganizationIntegration | null,
  ): EmployeeOrgIntegrationStatus {
    if (!integration) return 'not_enabled';
    if (integration.status === 'active') return 'active';
    if (integration.status === 'pending') return 'pending';
    return 'disabled';
  }
}
