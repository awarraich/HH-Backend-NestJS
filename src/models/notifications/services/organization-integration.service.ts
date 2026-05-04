import {
  Injectable,
  BadRequestException,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { In, Repository } from 'typeorm';
import { OrganizationIntegration } from '../entities/organization-integration.entity';
import { UserChatConnection } from '../entities/user-chat-connection.entity';
import { User } from '../../../authentication/entities/user.entity';
import { OrganizationStaff } from '../../organizations/staff-management/entities/organization-staff.entity';
import { Organization } from '../../organizations/entities/organization.entity';
import { Employee } from '../../employees/entities/employee.entity';
import { GoogleChatChannelService } from './channels/google-chat-channel.service';
import { GoogleChatConfigService } from '../../../config/google-chat/config.service';
import { ReminderKind } from '../entities/notification-dispatch-log.entity';

export interface EnableGoogleChatInput {
  workspaceDomain: string;
}

export interface UpdateConfigInput {
  cadence?: ReminderKind[];
  fallback_to_email?: boolean;
  allow_personal_accounts?: boolean;
}

export interface EmployeeConnectionRow {
  user_id: string;
  email: string;
  name: string;
  status: 'connected' | 'not_connected' | 'email_only' | 'revoked';
  connected_at: Date | null;
}

@Injectable()
export class OrganizationIntegrationService {
  constructor(
    @InjectRepository(OrganizationIntegration)
    private readonly integrations: Repository<OrganizationIntegration>,
    @InjectRepository(UserChatConnection)
    private readonly connections: Repository<UserChatConnection>,
    @InjectRepository(User) private readonly users: Repository<User>,
    @InjectRepository(OrganizationStaff)
    private readonly orgStaff: Repository<OrganizationStaff>,
    @InjectRepository(Organization)
    private readonly orgs: Repository<Organization>,
    @InjectRepository(Employee)
    private readonly employees: Repository<Employee>,
    private readonly chatChannel: GoogleChatChannelService,
    private readonly chatConfig: GoogleChatConfigService,
  ) {}

  /**
   * URL the wizard's "Install bot" button opens. Pre-Marketplace, falls back
   * to the same Chat user-add deep link the employee flow uses. Post-Marketplace,
   * `GOOGLE_CHAT_ADMIN_INSTALL_URL` should be set to a direct admin-install
   * URL (e.g. https://admin.google.com/ac/marketplace/app/.../install) which
   * drops the Workspace admin straight onto the install confirmation modal.
   */
  getInstallUrl(): string {
    const explicit = this.chatConfig.adminInstallUrl;
    if (explicit) return explicit;
    const appId = this.chatConfig.appId;
    if (!appId) return '';
    return `https://chat.google.com/u/0/app/${appId}`;
  }

  async enable(
    orgId: string,
    input: EnableGoogleChatInput,
    actor: { userId: string; email: string },
  ): Promise<OrganizationIntegration> {
    const workspaceDomain = input.workspaceDomain.trim().toLowerCase();
    const adminEmailDomain = (actor.email.split('@')[1] ?? '').toLowerCase();
    if (workspaceDomain !== adminEmailDomain) {
      throw new BadRequestException(
        `Workspace domain (${workspaceDomain}) must match your email domain (${adminEmailDomain}). This prevents tenants from claiming each other's domains.`,
      );
    }

    const existing = await this.integrations.findOne({
      where: { org_id: orgId, provider: 'google_chat' },
    });

    if (existing) {
      existing.workspace_domain = workspaceDomain;
      existing.status = existing.status === 'active' ? 'active' : 'pending';
      existing.enabled_by_user_id = actor.userId;
      existing.enabled_at = existing.enabled_at ?? new Date();
      existing.disabled_at = null;
      return this.integrations.save(existing);
    }

    const fresh = this.integrations.create({
      org_id: orgId,
      provider: 'google_chat',
      status: 'pending',
      workspace_domain: workspaceDomain,
      enabled_by_user_id: actor.userId,
      enabled_at: new Date(),
    });
    return this.integrations.save(fresh);
  }

  async verify(
    orgId: string,
    actor: { userId: string; email: string },
  ): Promise<OrganizationIntegration> {
    const integration = await this.requireIntegration(orgId);

    const connection = await this.connections.findOne({
      where: { user_id: actor.userId, provider: 'google_chat' },
    });
    if (!connection || connection.status !== 'connected' || !connection.dm_space_name) {
      throw new BadRequestException(
        'You need to add the HomeHealth Reminders bot to your own Google Chat first. Open Chat → New chat → search "HomeHealth Reminders" → Add. Then try Verify again.',
      );
    }

    try {
      await this.chatChannel.sendDirectMessage(
        connection.dm_space_name,
        '✅ HomeHealth Chat integration verified for your organization. Your team will start receiving document expiration reminders here.',
      );
    } catch (err) {
      throw new BadRequestException(
        `Verification DM failed: ${(err as Error).message}. Make sure the bot is still added to your Chat.`,
      );
    }

    integration.status = 'active';
    integration.verified_at = new Date();
    return this.integrations.save(integration);
  }

  async updateConfig(orgId: string, input: UpdateConfigInput): Promise<OrganizationIntegration> {
    const integration = await this.requireIntegration(orgId);
    integration.config = {
      ...(integration.config ?? {}),
      ...input,
    };
    return this.integrations.save(integration);
  }

  async disable(orgId: string): Promise<OrganizationIntegration> {
    const integration = await this.requireIntegration(orgId);
    integration.status = 'disabled';
    integration.disabled_at = new Date();
    return this.integrations.save(integration);
  }

  async getStatus(orgId: string): Promise<OrganizationIntegration | null> {
    return this.integrations.findOne({
      where: { org_id: orgId, provider: 'google_chat' },
    });
  }

  /**
   * Lists everyone in the org (admin manage-page view). Membership is the
   * union of three signals per architectural decision #8: owner via
   * `organizations.user_id`, ACTIVE staff via `organization_staff`, and
   * ACTIVE employees via `employees`. Deduped by user_id. Each user is
   * decorated with their Google Chat connection status if any.
   */
  async listEmployees(orgId: string): Promise<EmployeeConnectionRow[]> {
    const [org, staff, employeeRows] = await Promise.all([
      this.orgs.findOne({ where: { id: orgId } }),
      this.orgStaff.find({ where: { organization_id: orgId, status: 'ACTIVE' } }),
      this.employees.find({
        where: { organization_id: orgId, status: In(['ACTIVE', 'active']) },
      }),
    ]);

    const userIds = [
      ...new Set<string>([
        ...(org?.user_id ? [org.user_id] : []),
        ...staff.map((s) => s.user_id),
        ...employeeRows.map((e) => e.user_id),
      ]),
    ];
    if (userIds.length === 0) return [];

    const users = await this.users.find({ where: { id: In(userIds) } });
    const usersById = new Map(users.map((u) => [u.id, u]));

    const connections = await this.connections.find({
      where: { user_id: In(userIds), provider: 'google_chat' },
    });
    const connectionsByUserId = new Map(connections.map((c) => [c.user_id, c]));

    return userIds.map((userId) => {
      const user = usersById.get(userId);
      const conn = connectionsByUserId.get(userId);
      let status: EmployeeConnectionRow['status'];
      if (!conn) status = 'not_connected';
      else if (conn.status === 'revoked') status = 'revoked';
      else if (!conn.chat_eligible) status = 'email_only';
      else if (conn.status === 'connected') status = 'connected';
      else status = 'not_connected';

      return {
        user_id: userId,
        email: user?.email ?? '',
        name: user ? `${user.firstName} ${user.lastName}` : '',
        status,
        connected_at: conn?.connected_at ?? null,
      };
    });
  }

  private async requireIntegration(orgId: string): Promise<OrganizationIntegration> {
    const integration = await this.integrations.findOne({
      where: { org_id: orgId, provider: 'google_chat' },
    });
    if (!integration) {
      throw new NotFoundException(
        `No Google Chat integration found for org ${orgId}. Enable it first.`,
      );
    }
    return integration;
  }
}
