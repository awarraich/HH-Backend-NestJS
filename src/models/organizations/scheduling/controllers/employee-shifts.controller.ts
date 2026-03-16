import {
  Controller,
  Get,
  Patch,
  Delete,
  Body,
  Param,
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
import { UpdateEmployeeShiftDto } from '../dto/update-employee-shift.dto';

type RequestWithUser = FastifyRequest & { user?: { userId?: string; sub?: string } };

@Controller('v1/api/organizations/:organizationId/employee-shifts')
@UseGuards(JwtAuthGuard, OrganizationRoleGuard)
@Roles('OWNER', 'HR', 'MANAGER')
export class EmployeeShiftsController {
  constructor(private readonly employeeShiftService: EmployeeShiftService) {}

  @Get(':employeeShiftId')
  @HttpCode(HttpStatus.OK)
  async findOne(
    @Param('organizationId') organizationId: string,
    @Param('employeeShiftId') employeeShiftId: string,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.employeeShiftService.findOne(organizationId, employeeShiftId, userId);
    return SuccessHelper.createSuccessResponse(data);
  }

  @Patch(':employeeShiftId')
  @HttpCode(HttpStatus.OK)
  async update(
    @Param('organizationId') organizationId: string,
    @Param('employeeShiftId') employeeShiftId: string,
    @Body() dto: UpdateEmployeeShiftDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.employeeShiftService.update(
      organizationId,
      employeeShiftId,
      dto,
      userId,
    );
    return SuccessHelper.createSuccessResponse(data);
  }

  @Delete(':employeeShiftId')
  @HttpCode(HttpStatus.OK)
  async remove(
    @Param('organizationId') organizationId: string,
    @Param('employeeShiftId') employeeShiftId: string,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    await this.employeeShiftService.remove(organizationId, employeeShiftId, userId);
    return SuccessHelper.createSuccessResponse(null, 'Employee shift removed');
  }
}
