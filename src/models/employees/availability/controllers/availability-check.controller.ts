import {
  Controller,
  Get,
  NotFoundException,
  Param,
  Query,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { JwtAuthGuard } from '../../../../common/guards/jwt-auth.guard';
import { OrganizationRoleGuard } from '../../../../common/guards/organization-role.guard';
import { Roles } from '../../../../common/decorators/roles.decorator';
import { SuccessHelper } from '../../../../common/helpers/responses/success.helper';
import { AvailabilityRuleService } from '../services/availability-rule.service';
import { Employee } from '../../entities/employee.entity';
import { AvailabilityCheckDto } from '../dto/availability-check.dto';

/**
 * Org-side availability lookup powering the scheduling picker. One round-trip
 * returns the status for every employee the manager could choose. Restricted
 * to organization staff; an employee can already see their own rules via
 * /v1/api/employee/calendar/availability.
 */
@Controller('v1/api/organizations/:organizationId/availability-check')
@UseGuards(JwtAuthGuard, OrganizationRoleGuard)
@Roles('OWNER', 'HR', 'MANAGER')
export class AvailabilityCheckController {
  constructor(
    private readonly availabilityRuleService: AvailabilityRuleService,
    @InjectRepository(Employee)
    private readonly employeeRepository: Repository<Employee>,
  ) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async check(
    @Param('organizationId') organizationId: string,
    @Query() query: AvailabilityCheckDto,
  ) {
    // Resolve the candidate employee_ids to user_ids — availability rules
    // live per user, but the scheduling page identifies people by the
    // org-scoped Employee row. Loading by employee.id (one query) keeps
    // the path the same whether the caller passed 1 id or 50.
    const employeeIds =
      query.employee_ids && query.employee_ids.length > 0
        ? query.employee_ids
        : (
            await this.employeeRepository.find({
              where: { organization_id: organizationId },
              select: ['id'],
            })
          ).map((e) => e.id);

    if (employeeIds.length === 0) {
      return SuccessHelper.createSuccessResponse({});
    }

    const employees = await this.employeeRepository.find({
      where: employeeIds.map((id) => ({ id, organization_id: organizationId })),
      select: ['id', 'user_id'],
    });
    const userIdByEmployeeId = new Map(employees.map((e) => [e.id, e.user_id]));
    const userIds = employees.map((e) => e.user_id);

    const byUser = await this.availabilityRuleService.checkAvailabilityBulk(
      userIds,
      organizationId,
      query.date,
      query.start_time,
      query.end_time,
    );

    // Echo results keyed by employee_id (what the FE actually has handles for).
    const byEmployee: Record<string, (typeof byUser)[string]> = {};
    for (const [empId, userId] of userIdByEmployeeId.entries()) {
      const r = byUser[userId];
      if (r) byEmployee[empId] = r;
    }
    return SuccessHelper.createSuccessResponse(byEmployee);
  }

  /**
   * HR-side full availability rules for a single employee. Powers the
   * "Availability" tab on the HR File detail page so HR can see the same
   * weekly pattern + date overrides the employee maintains for themselves.
   * Read-only — edits stay on the employee side.
   */
  @Get('employees/:employeeId/rules')
  @HttpCode(HttpStatus.OK)
  async getRulesForEmployee(
    @Param('organizationId') organizationId: string,
    @Param('employeeId') employeeId: string,
  ) {
    const employee = await this.employeeRepository.findOne({
      where: { id: employeeId, organization_id: organizationId },
      select: ['id', 'user_id'],
    });
    if (!employee) {
      throw new NotFoundException('Employee not found in this organization');
    }

    const rules = await this.availabilityRuleService.findByUser(
      employee.user_id,
      organizationId,
    );
    return SuccessHelper.createSuccessResponse(rules);
  }
}
