import {
  Controller,
  Get,
  Post,
  Patch,
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
import { ShiftService } from '../services/shift.service';
import { EmployeeShiftService } from '../services/employee-shift.service';
import { CreateShiftDto } from '../dto/create-shift.dto';
import { UpdateShiftDto } from '../dto/update-shift.dto';
import { QueryShiftDto } from '../dto/query-shift.dto';
import { CreateEmployeeShiftDto } from '../dto/create-employee-shift.dto';
import { QueryEmployeeShiftDto } from '../dto/query-employee-shift.dto';

type RequestWithUser = FastifyRequest & { user?: { userId?: string; sub?: string } };

@Controller('v1/api/organizations/:organizationId/shifts')
@UseGuards(JwtAuthGuard, OrganizationRoleGuard)
@Roles('OWNER', 'HR', 'MANAGER')
export class ShiftsController {
  constructor(
    private readonly shiftService: ShiftService,
    private readonly employeeShiftService: EmployeeShiftService,
  ) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async findAll(
    @Param('organizationId') organizationId: string,
    @Query() query: QueryShiftDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const result = await this.shiftService.findAll(organizationId, query, userId);
    return SuccessHelper.createPaginatedResponse(
      result.data,
      result.total,
      result.page,
      result.limit,
    );
  }

  @Get(':shiftId/employee-shifts')
  @HttpCode(HttpStatus.OK)
  async findEmployeeShifts(
    @Param('organizationId') organizationId: string,
    @Param('shiftId') shiftId: string,
    @Query() query: QueryEmployeeShiftDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const result = await this.employeeShiftService.findByShift(
      organizationId,
      shiftId,
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

  @Post(':shiftId/employee-shifts')
  @HttpCode(HttpStatus.CREATED)
  async createEmployeeShift(
    @Param('organizationId') organizationId: string,
    @Param('shiftId') shiftId: string,
    @Body() dto: CreateEmployeeShiftDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.employeeShiftService.create(
      organizationId,
      shiftId,
      dto,
      userId,
    );
    return SuccessHelper.createSuccessResponse(data);
  }

  @Get(':shiftId')
  @HttpCode(HttpStatus.OK)
  async findOne(
    @Param('organizationId') organizationId: string,
    @Param('shiftId') shiftId: string,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.shiftService.findOne(organizationId, shiftId, userId);
    return SuccessHelper.createSuccessResponse(data);
  }

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async create(
    @Param('organizationId') organizationId: string,
    @Body() dto: CreateShiftDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.shiftService.create(organizationId, dto, userId);
    return SuccessHelper.createSuccessResponse(data);
  }

  @Patch(':shiftId')
  @HttpCode(HttpStatus.OK)
  async update(
    @Param('organizationId') organizationId: string,
    @Param('shiftId') shiftId: string,
    @Body() dto: UpdateShiftDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.shiftService.update(
      organizationId,
      shiftId,
      dto,
      userId,
    );
    return SuccessHelper.createSuccessResponse(data);
  }

  @Delete(':shiftId')
  @HttpCode(HttpStatus.OK)
  async remove(
    @Param('organizationId') organizationId: string,
    @Param('shiftId') shiftId: string,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    await this.shiftService.remove(organizationId, shiftId, userId);
    return SuccessHelper.createSuccessResponse(null, 'Shift deleted');
  }
}
