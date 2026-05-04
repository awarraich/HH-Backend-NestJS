import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { In, Repository } from 'typeorm';
import { User } from '../../../authentication/entities/user.entity';
import { OrganizationStaff } from '../../organizations/staff-management/entities/organization-staff.entity';
import { Organization } from '../../organizations/entities/organization.entity';
import { Employee } from '../../employees/entities/employee.entity';
import { OrganizationIntegration } from '../entities/organization-integration.entity';
import { UserChatConnection } from '../entities/user-chat-connection.entity';

export interface GoogleChatEventPayload {
  type?: string;
  user?: { name?: string; displayName?: string; email?: string };
  space?: { name?: string };
}

export interface BotReply {
  text: string;
}

@Injectable()
export class BotEventHandlerService {
  private readonly logger = new Logger(BotEventHandlerService.name);

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
  ) {}

  async handleAddedToSpace(event: GoogleChatEventPayload): Promise<BotReply> {
    const email = event.user?.email;
    const chatUserId = event.user?.name;
    const dmSpaceName = event.space?.name;
    const displayName = event.user?.displayName ?? 'there';

    if (!email || !chatUserId || !dmSpaceName) {
      this.logger.warn(`ADDED_TO_SPACE missing required fields`);
      return {
        text: 'Connection failed — missing required event fields. Please contact support.',
      };
    }

    const user = await this.users.findOne({ where: { email } });
    if (!user) {
      this.logger.warn(`ADDED_TO_SPACE: no HomeHealth user with email ${email}`);
      return {
        text: `This Google account isn't linked to any HomeHealth employee. Ask your admin to add ${email} to HomeHealth first.`,
      };
    }

    // Membership = owner + staff + employee (architectural decision #8). Mirrors
    // EmployeeNotificationsService.findUsersOrgIntegration so the bot-add path
    // and the notifications-page path agree on who belongs to what.
    const [ownerOrgs, staffRows, employeeRows] = await Promise.all([
      this.orgs.find({ where: { user_id: user.id } }),
      this.orgStaff.find({ where: { user_id: user.id, status: 'ACTIVE' } }),
      this.employees.find({
        where: { user_id: user.id, status: In(['ACTIVE', 'active']) },
      }),
    ]);
    const orgIds = [
      ...new Set<string>([
        ...ownerOrgs.map((o) => o.id),
        ...staffRows.map((s) => s.organization_id),
        ...employeeRows
          .map((e) => e.organization_id)
          .filter((id): id is string => Boolean(id)),
      ]),
    ];
    if (orgIds.length === 0) {
      return {
        text: `Hi ${displayName}, your HomeHealth account isn't currently active in any organization.`,
      };
    }

    const activeIntegrations = await this.orgIntegrations.find({
      where: { provider: 'google_chat', status: 'active', org_id: In(orgIds) },
    });

    if (activeIntegrations.length === 0) {
      return {
        text: `Hi ${displayName}, your organization hasn't enabled HomeHealth Chat reminders yet. Ask your admin to enable it in Settings → Integrations.`,
      };
    }

    if (activeIntegrations.length > 1) {
      this.logger.warn(
        `User ${user.id} (${email}) is staffed at ${activeIntegrations.length} orgs with active Chat integrations — picking the first by org_id. Cross-tenant employees: see design doc open question #4.`,
      );
    }
    const integration = activeIntegrations[0];

    const chatEligible = this.isChatEligible(email, integration.workspace_domain);

    const existing = await this.connections.findOne({
      where: { user_id: user.id, provider: 'google_chat' },
    });

    const now = new Date();
    if (existing) {
      existing.org_id = integration.org_id;
      existing.chat_user_id = chatUserId;
      existing.dm_space_name = dmSpaceName;
      existing.status = 'connected';
      existing.chat_eligible = chatEligible;
      existing.connected_at = now;
      existing.revoked_at = null;
      await this.connections.save(existing);
    } else {
      const fresh = this.connections.create({
        user_id: user.id,
        org_id: integration.org_id,
        provider: 'google_chat',
        chat_user_id: chatUserId,
        dm_space_name: dmSpaceName,
        status: 'connected',
        chat_eligible: chatEligible,
        connected_at: now,
      });
      await this.connections.save(fresh);
    }

    if (!chatEligible) {
      return {
        text: `Hi ${displayName}, this account (${email}) isn't on your organization's Google Workspace, so document reminders will continue to be sent by email instead of Chat. Talk to your admin if you'd like a Workspace account.`,
      };
    }

    return {
      text: `Hi ${displayName}, you're connected to HomeHealth Reminders. I'll DM you about expiring documents.`,
    };
  }

  async handleRemovedFromSpace(event: GoogleChatEventPayload): Promise<void> {
    const email = event.user?.email;
    if (!email) return;

    const user = await this.users.findOne({ where: { email } });
    if (!user) return;

    const connection = await this.connections.findOne({
      where: { user_id: user.id, provider: 'google_chat' },
    });
    if (!connection) return;

    connection.status = 'revoked';
    connection.revoked_at = new Date();
    await this.connections.save(connection);
    this.logger.log(`Connection revoked for user ${user.id} (${email})`);
  }

  handleMessage(): BotReply {
    return {
      text: 'This is a notifications-only bot. Open HomeHealth to manage your documents.',
    };
  }

  private isChatEligible(email: string, workspaceDomain: string | null): boolean {
    if (!workspaceDomain) return true;
    const emailDomain = (email.split('@')[1] ?? '').toLowerCase();
    return emailDomain === workspaceDomain.toLowerCase();
  }
}
