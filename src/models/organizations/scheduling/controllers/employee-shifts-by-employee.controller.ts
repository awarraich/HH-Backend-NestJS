import {
  Controller,
  Get,
  Param,
  Query,
  UseGuards,
  Request,
  HttpCode,
  HttpStatus,
  UnauthorizedException,
} from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import { JwtAuthGuard } from '../../../../common/guards/jwt-auth.guard';
import { OrganizationRoleGuard } from '../../../../common/guards/organization-role.guard';
import { Roles } from '../../../../common/decorators/roles.decorator';
import { SuccessHelper } from '../../../../common/helpers/responses/success.helper';
import { EmployeeShiftService } from '../services/employee-shift.service';
import { QueryEmployeeShiftsByEmployeeDto } from '../dto/query-employee-shifts-by-employee.dto';

type RequestWithUser = FastifyRequest & { user?: { userId?: string; sub?: string } };

@Controller('v1/api/organizations/:organizationId/employees')
@UseGuards(JwtAuthGuard, OrganizationRoleGuard)
@Roles('OWNER', 'HR', 'MANAGER')
export class EmployeeShiftsByEmployeeController {
  constructor(private readonly employeeShiftService: EmployeeShiftService) {}

  @Get(':employeeId/shifts')
  @HttpCode(HttpStatus.OK)
  async findByEmployee(
    @Param('organizationId') organizationId: string,
    @Param('employeeId') employeeId: string,
    @Query() query: QueryEmployeeShiftsByEmployeeDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const result = await this.employeeShiftService.findByEmployee(
      organizationId,
      employeeId,
      query,
      userId,
    );
    return SuccessHelper.createPaginatedResponse(
      result.data,
      result.total,
      result.page,
      result.limit,
    );
  }
}
