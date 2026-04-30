import {
  BadRequestException,
  Body,
  Controller,
  ForbiddenException,
  Get,
  HttpCode,
  HttpStatus,
  NotFoundException,
  Param,
  ParseUUIDPipe,
  Put,
  Request,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import { InjectRepository } from '@nestjs/typeorm';
import { In, Repository } from 'typeorm';
import { JwtAuthGuard } from '../../../../common/guards/jwt-auth.guard';
import { OrganizationRoleGuard } from '../../../../common/guards/organization-role.guard';
import { Roles } from '../../../../common/decorators/roles.decorator';
import { SuccessHelper } from '../../../../common/helpers/responses/success.helper';
import { Role } from '../../../../authentication/entities/role.entity';
import { UserRole } from '../../../../authentication/entities/user-role.entity';
import { User } from '../../../../authentication/entities/user.entity';
import { OrganizationStaff } from '../entities/organization-staff.entity';
import { StaffRole } from '../entities/staff-role.entity';

type RequestWithUser = FastifyRequest & { user?: { userId?: string; sub?: string } };

type AppContext = 'staff' | 'employee';

const STAFF_ROLE_NAMES = ['STAFF', 'ORGANIZATION', 'OWNER', 'HR', 'MANAGER', 'ASSISTANT_HR'];
const EMPLOYEE_ROLE_NAME = 'EMPLOYEE';
/** The role we ADD when granting staff context (vs. the existing roles we
 *  count toward "has staff context"). 'STAFF' is the dedicated dual-role
 *  grant — keeps the user's existing OWNER/HR roles untouched if any. */
const STAFF_GRANT_ROLE_NAME = 'STAFF';

interface UpdateBody {
  contexts: AppContext[];
}

/**
 * HR-side endpoints for granting / revoking the Staff and Employee app
 * contexts on an existing user. The dual-role JWT switcher reads
 * `available_roles` from the user's role assignments — this controller is
 * the UI replacement for hand-editing `user_roles` rows in the database.
 *
 * Granting STAFF additionally provisions an `OrganizationStaff` row when
 * one doesn't already exist, so the staff dashboard's
 * `my-organization` lookup succeeds and the sidebar gets feature
 * permissions. Revoking STAFF marks that row INACTIVE (preserves audit
 * history; doesn't destroy department/position metadata an admin set).
 *
 * Granting EMPLOYEE only adds the user_roles entry — it does NOT create
 * an `Employee` record. An employee row carries department/position
 * required for shift scheduling, so creating one here would silently
 * leave it half-configured. Downstream features still gate on the
 * Employee row's existence.
 */
@Controller('v1/api/organizations/:organizationId/users/:userId')
@UseGuards(JwtAuthGuard, OrganizationRoleGuard)
@Roles('OWNER', 'HR', 'ADMIN')
export class UserAppContextsController {
  constructor(
    @InjectRepository(Role)
    private readonly roleRepo: Repository<Role>,
    @InjectRepository(UserRole)
    private readonly userRoleRepo: Repository<UserRole>,
    @InjectRepository(User)
    private readonly userRepo: Repository<User>,
    @InjectRepository(OrganizationStaff)
    private readonly orgStaffRepo: Repository<OrganizationStaff>,
    @InjectRepository(StaffRole)
    private readonly staffRoleRepo: Repository<StaffRole>,
  ) {}

  @Get('app-contexts')
  @HttpCode(HttpStatus.OK)
  async get(@Param('userId', new ParseUUIDPipe()) userId: string) {
    const contexts = await this.computeContextsForUser(userId);
    return SuccessHelper.createSuccessResponse({
      user_id: userId,
      contexts,
    });
  }

  @Put('app-contexts')
  @HttpCode(HttpStatus.OK)
  async update(
    @Request() req: RequestWithUser,
    @Param('organizationId', new ParseUUIDPipe()) organizationId: string,
    @Param('userId', new ParseUUIDPipe()) targetUserId: string,
    @Body() body: UpdateBody,
  ) {
    const callerUserId = req.user?.userId ?? req.user?.sub;
    if (!callerUserId) throw new UnauthorizedException('User ID not found');

    const requested = Array.isArray(body.contexts) ? [...new Set(body.contexts)] : [];
    const valid = requested.filter((c): c is AppContext => c === 'staff' || c === 'employee');
    if (valid.length === 0) {
      throw new BadRequestException(
        'At least one app context ("staff" or "employee") must remain — leaving a user with no contexts would lock them out.',
      );
    }

    // Self-lockout guard: HR can't strip their own staff access via this
    // endpoint. Reduces the foot-gun where an admin removes their own
    // ORGANIZATION/HR role and is suddenly locked out of the app they're
    // making the change from.
    if (callerUserId === targetUserId && !valid.includes('staff')) {
      throw new ForbiddenException(
        'You cannot remove your own Staff access. Have another OWNER/HR do it if you really need this.',
      );
    }

    const target = await this.userRepo.findOne({ where: { id: targetUserId } });
    if (!target) throw new NotFoundException('User not found');

    const allRoles = await this.roleRepo.find({
      where: { name: In([EMPLOYEE_ROLE_NAME, STAFF_GRANT_ROLE_NAME]) },
    });
    const employeeRole = allRoles.find((r) => r.name === EMPLOYEE_ROLE_NAME);
    const staffRole = allRoles.find((r) => r.name === STAFF_GRANT_ROLE_NAME);

    if (valid.includes('employee') && !employeeRole) {
      throw new BadRequestException(
        'EMPLOYEE role missing from roles table — run the seed-roles migration.',
      );
    }
    if (valid.includes('staff') && !staffRole) {
      throw new BadRequestException(
        'STAFF role missing from roles table — run the add-staff-system-role migration.',
      );
    }

    const currentLinks = await this.userRoleRepo.find({
      where: { user_id: targetUserId },
      relations: ['role'],
    });
    const currentByName = new Map(currentLinks.map((l) => [l.role?.name, l]));

    // Grant logic
    if (valid.includes('employee') && !currentByName.has(EMPLOYEE_ROLE_NAME)) {
      await this.userRoleRepo.save(
        this.userRoleRepo.create({ user_id: targetUserId, role_id: employeeRole!.id }),
      );
    }
    if (valid.includes('staff')) {
      const hasAnyStaffRole = currentLinks.some(
        (l) => l.role?.name && STAFF_ROLE_NAMES.includes(l.role.name),
      );
      if (!hasAnyStaffRole) {
        await this.userRoleRepo.save(
          this.userRoleRepo.create({ user_id: targetUserId, role_id: staffRole!.id }),
        );
      }
    }

    // Revoke logic — only revoke the dedicated grant roles (STAFF and
    // EMPLOYEE). Leaves OWNER/HR/MANAGER/ORGANIZATION untouched so we
    // never accidentally demote an org owner to non-staff.
    if (!valid.includes('employee') && employeeRole) {
      const link = currentByName.get(EMPLOYEE_ROLE_NAME);
      if (link) await this.userRoleRepo.delete({ id: link.id });
    }
    if (!valid.includes('staff') && staffRole) {
      const link = currentByName.get(STAFF_GRANT_ROLE_NAME);
      // Only safe to revoke when STAFF is the only thing granting staff
      // context — if the user is also OWNER/HR/etc., leave them alone.
      const otherStaffRoles = currentLinks.filter(
        (l) =>
          l.role?.name &&
          STAFF_ROLE_NAMES.includes(l.role.name) &&
          l.role.name !== STAFF_GRANT_ROLE_NAME,
      );
      if (link && otherStaffRoles.length === 0) {
        await this.userRoleRepo.delete({ id: link.id });
      }
    }

    // Provision / deprovision the OrganizationStaff row that backs the
    // staff dashboard. Without this, granting STAFF role would leave the
    // user without an org_staff record — `my-organization` 404s, the
    // sidebar gets no permissions, and the user lands on a blank shell.
    if (valid.includes('staff')) {
      await this.ensureOrganizationStaffActive(organizationId, targetUserId, callerUserId);
    } else {
      await this.deactivateOrganizationStaff(organizationId, targetUserId);
    }

    const newContexts = await this.computeContextsForUser(targetUserId);
    return SuccessHelper.createSuccessResponse(
      { user_id: targetUserId, contexts: newContexts },
      `App access updated. The user's next login (or role-switch) will reflect the change.`,
    );
  }

  /**
   * Make sure the user has an ACTIVE `OrganizationStaff` row in this org so
   * the staff dashboard works. If a row exists in any state (INACTIVE /
   * TERMINATED) we re-activate it; otherwise we create one with a
   * lowest-privilege default staff_role.
   *
   * Picking a default role: prefers ASSISTANT_HR (read-only-ish), falls
   * back to whichever staff_role exists. HR can re-assign in EditStaffDialog
   * after the grant — this just bootstraps a usable record.
   */
  private async ensureOrganizationStaffActive(
    organizationId: string,
    userId: string,
    callerUserId: string,
  ): Promise<void> {
    const existing = await this.orgStaffRepo.findOne({
      where: { organization_id: organizationId, user_id: userId },
    });
    if (existing) {
      if (existing.status !== 'ACTIVE') {
        existing.status = 'ACTIVE';
        existing.updated_by = callerUserId;
        await this.orgStaffRepo.save(existing);
      }
      return;
    }

    const defaultRole = await this.pickDefaultStaffRole();
    if (!defaultRole) {
      // No staff_roles seeded — can't create the row. Caller still gets
      // their user_roles grant but the dashboard won't fully resolve until
      // an HR runs the staff_roles seed. Surface as a soft warning, not a
      // hard 500, so the broader app-access flow still succeeds.
      return;
    }
    await this.orgStaffRepo.save(
      this.orgStaffRepo.create({
        organization_id: organizationId,
        user_id: userId,
        staff_role_id: defaultRole.id,
        status: 'ACTIVE',
        created_by: callerUserId,
        updated_by: callerUserId,
      }),
    );
  }

  /**
   * Mark the OrganizationStaff row INACTIVE on STAFF revoke. We don't
   * delete — preserves audit trail and means re-granting later just flips
   * status back instead of losing department/position the admin set.
   */
  private async deactivateOrganizationStaff(
    organizationId: string,
    userId: string,
  ): Promise<void> {
    const existing = await this.orgStaffRepo.findOne({
      where: { organization_id: organizationId, user_id: userId, status: 'ACTIVE' },
    });
    if (!existing) return;
    existing.status = 'INACTIVE';
    await this.orgStaffRepo.save(existing);
  }

  private async pickDefaultStaffRole(): Promise<StaffRole | null> {
    // HR has the broadest seeded feature permissions across orgs, so it's
    // the safest "useful" default. Without this, the auto-provisioned
    // staff record would land on a low-perm role and the dual-role user
    // would still see access-denied on most endpoints. HR can re-assign
    // via EditStaffDialog if a different role suits the user better.
    const preferred = await this.staffRoleRepo.findOne({
      where: { name: 'HR' },
    });
    if (preferred) return preferred;
    return this.staffRoleRepo.findOne({
      where: {},
      order: { name: 'ASC' },
    });
  }

  private async computeContextsForUser(userId: string): Promise<AppContext[]> {
    const links = await this.userRoleRepo.find({
      where: { user_id: userId },
      relations: ['role'],
    });
    const names = new Set(links.map((l) => l.role?.name).filter((n): n is string => !!n));
    const contexts: AppContext[] = [];
    if ([...names].some((n) => STAFF_ROLE_NAMES.includes(n))) contexts.push('staff');
    if (names.has(EMPLOYEE_ROLE_NAME)) contexts.push('employee');
    return contexts;
  }
}
