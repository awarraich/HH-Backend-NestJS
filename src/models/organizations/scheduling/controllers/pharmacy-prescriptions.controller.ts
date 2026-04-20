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
import { ScheduledTaskService } from '../services/scheduled-task.service';
import {
  CreatePharmacyPrescriptionDto,
  UpdatePharmacyPrescriptionDto,
  QueryPharmacyPrescriptionDto,
} from '../dto/pharmacy-prescription.dto';
import {
  TransitionScheduledTaskStatusDto,
  CreateScheduledTaskAssignmentDto,
} from '../dto/scheduled-task-base.dto';

type RequestWithUser = FastifyRequest & { user?: { userId?: string; sub?: string } };

const TASK_TYPE = 'pharmacy_prescription';

@Controller('v1/api/organizations/:organizationId/pharmacy-prescriptions')
@UseGuards(JwtAuthGuard, OrganizationRoleGuard)
@Roles('OWNER', 'HR', 'MANAGER')
export class PharmacyPrescriptionsController {
  constructor(private readonly taskService: ScheduledTaskService) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async findAll(
    @Param('organizationId') organizationId: string,
    @Query() query: QueryPharmacyPrescriptionDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const result = await this.taskService.list(organizationId, TASK_TYPE, query, userId);
    return SuccessHelper.createPaginatedResponse(
      result.data,
      result.total,
      result.page,
      result.limit,
    );
  }

  @Get(':id')
  @HttpCode(HttpStatus.OK)
  async findOne(
    @Param('organizationId') organizationId: string,
    @Param('id') id: string,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.taskService.findOne(organizationId, TASK_TYPE, id, userId);
    return SuccessHelper.createSuccessResponse(data);
  }

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async create(
    @Param('organizationId') organizationId: string,
    @Body() dto: CreatePharmacyPrescriptionDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.taskService.create(organizationId, TASK_TYPE, dto, userId);
    return SuccessHelper.createSuccessResponse(data, 'Prescription created');
  }

  @Patch(':id')
  @HttpCode(HttpStatus.OK)
  async update(
    @Param('organizationId') organizationId: string,
    @Param('id') id: string,
    @Body() dto: UpdatePharmacyPrescriptionDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.taskService.update(organizationId, TASK_TYPE, id, dto, userId);
    return SuccessHelper.createSuccessResponse(data, 'Prescription updated');
  }

  @Delete(':id')
  @HttpCode(HttpStatus.OK)
  async remove(
    @Param('organizationId') organizationId: string,
    @Param('id') id: string,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    await this.taskService.remove(organizationId, TASK_TYPE, id, userId);
    return SuccessHelper.createSuccessResponse(null, 'Prescription removed');
  }

  @Post(':id/status')
  @HttpCode(HttpStatus.OK)
  async transitionStatus(
    @Param('organizationId') organizationId: string,
    @Param('id') id: string,
    @Body() dto: TransitionScheduledTaskStatusDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.taskService.transitionStatus(
      organizationId,
      TASK_TYPE,
      id,
      dto,
      userId,
    );
    return SuccessHelper.createSuccessResponse(data, 'Status updated');
  }

  @Post(':id/assignments')
  @HttpCode(HttpStatus.CREATED)
  async addAssignment(
    @Param('organizationId') organizationId: string,
    @Param('id') id: string,
    @Body() dto: CreateScheduledTaskAssignmentDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.taskService.addAssignment(
      organizationId,
      TASK_TYPE,
      id,
      dto,
      userId,
    );
    return SuccessHelper.createSuccessResponse(data, 'Assignment added');
  }

  @Delete(':id/assignments/:assignmentId')
  @HttpCode(HttpStatus.OK)
  async removeAssignment(
    @Param('organizationId') organizationId: string,
    @Param('id') id: string,
    @Param('assignmentId') assignmentId: string,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    await this.taskService.removeAssignment(
      organizationId,
      TASK_TYPE,
      id,
      assignmentId,
      userId,
    );
    return SuccessHelper.createSuccessResponse(null, 'Assignment removed');
  }
}
