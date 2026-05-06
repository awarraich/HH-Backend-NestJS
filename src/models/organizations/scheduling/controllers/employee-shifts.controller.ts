import {
  Controller,
  Get,
  Patch,
  Post,
  Delete,
  Body,
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
import { UpdateEmployeeShiftDto } from '../dto/update-employee-shift.dto';
import { GetBedMapDto } from '../dto/get-bed-map.dto';
import { BulkClearEmployeeShiftsDto } from '../dto/bulk-clear-employee-shifts.dto';

type RequestWithUser = FastifyRequest & { user?: { userId?: string; sub?: string } };

@Controller('v1/api/organizations/:organizationId/employee-shifts')
@UseGuards(JwtAuthGuard, OrganizationRoleGuard)
@Roles('OWNER', 'HR', 'MANAGER')
export class EmployeeShiftsController {
  constructor(private readonly employeeShiftService: EmployeeShiftService) {}

  // ─── Static routes ─────────────────────────────────────────────────
  // These MUST be declared before the dynamic `:employeeShiftId` routes
  // so NestJS doesn't treat "bed-map" / "bulk-clear" as an id.

  /**
   * Comprehensive Bed Map snapshot for a (station, shift, date). Returns
   * rooms with their real bed + chair records eager-loaded, the live
   * employee_shift rows, and pre-computed stats — all in one call.
   *
   * shift_id + scheduled_date are optional; when omitted the response
   * still returns the room layout so the manager can pick a shift.
   */
  @Get('bed-map')
  @HttpCode(HttpStatus.OK)
  async getBedMap(
    @Param('organizationId') organizationId: string,
    @Query() query: GetBedMapDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.employeeShiftService.getBedMap(organizationId, query, userId);
    return SuccessHelper.createSuccessResponse(data);
  }

  /**
   * Atomic bulk delete of employee_shift rows scoped to a single room or
   * station for a (shift, date). Replaces the N sequential DELETEs the
   * front-end's "Clear room" action used to do.
   */
  @Post('bulk-clear')
  @HttpCode(HttpStatus.OK)
  async bulkClear(
    @Param('organizationId') organizationId: string,
    @Body() dto: BulkClearEmployeeShiftsDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.employeeShiftService.bulkClear(organizationId, dto, userId);
    return SuccessHelper.createSuccessResponse(data);
  }

  // ─── Dynamic routes ────────────────────────────────────────────────

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
