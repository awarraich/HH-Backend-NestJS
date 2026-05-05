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
  HttpCode,
  HttpStatus,
  UnauthorizedException,
  Request,
} from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import { JwtAuthGuard } from '../../../../common/guards/jwt-auth.guard';
import { OrganizationRoleGuard } from '../../../../common/guards/organization-role.guard';
import { Roles } from '../../../../common/decorators/roles.decorator';
import { SuccessHelper } from '../../../../common/helpers/responses/success.helper';
import { AssignmentsService } from '../services/assignments.service';
import { CreateAssignmentDto } from '../dto/create-assignment.dto';
import { FillAssignmentDto } from '../dto/fill-assignment.dto';
import { EmployeeSignDto } from '../dto/employee-sign.dto';

type RequestWithUser = FastifyRequest & {
  user?: { userId?: string; sub?: string };
};

@Controller('v1/api/organizations/:organizationId/document-workflow/assignments')
@UseGuards(JwtAuthGuard, OrganizationRoleGuard)
@Roles('OWNER', 'HR', 'MANAGER')
export class AssignmentsController {
  constructor(private readonly service: AssignmentsService) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async findAll(
    @Param('organizationId') orgId: string,
    @Query('status') status?: string,
    @Query('supervisor_id') supervisorId?: string,
  ) {
    const data = await this.service.findAll(orgId, { status, supervisorId });
    return SuccessHelper.createSuccessResponse(data);
  }

  @Get('supervisor/:userId')
  @HttpCode(HttpStatus.OK)
  async getForSupervisor(@Param('userId') userId: string) {
    const data = await this.service.getForSupervisor(userId);
    return SuccessHelper.createSuccessResponse(data);
  }

  /**
   * List every competency assignment in this org where the given user is
   * either the supervisor or appears on any template role. Backs the
   * "Document Workflows" panel on the employee HR File detail page.
   */
  @Get('employee/:userId')
  @HttpCode(HttpStatus.OK)
  async getForEmployee(
    @Param('organizationId') orgId: string,
    @Param('userId') userId: string,
  ) {
    const data = await this.service.getForEmployee(orgId, userId);
    return SuccessHelper.createSuccessResponse(data);
  }

  @Get(':id')
  @HttpCode(HttpStatus.OK)
  async findOne(
    @Param('organizationId') orgId: string,
    @Param('id') id: string,
  ) {
    const data = await this.service.findOne(orgId, id);
    return SuccessHelper.createSuccessResponse(data);
  }

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async create(
    @Param('organizationId') orgId: string,
    @Body() dto: CreateAssignmentDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.service.create(orgId, dto, userId);
    return SuccessHelper.createSuccessResponse(data, 'Assignment created.');
  }

  @Patch(':id/fill')
  @HttpCode(HttpStatus.OK)
  async fill(
    @Param('organizationId') orgId: string,
    @Param('id') id: string,
    @Body() dto: FillAssignmentDto,
  ) {
    const data = await this.service.fill(orgId, id, dto);
    return SuccessHelper.createSuccessResponse(data, 'Assignment updated.');
  }

  @Patch(':id/submit')
  @HttpCode(HttpStatus.OK)
  async submit(
    @Param('organizationId') orgId: string,
    @Param('id') id: string,
  ) {
    const data = await this.service.submit(orgId, id);
    return SuccessHelper.createSuccessResponse(data, 'Assignment completed.');
  }

  @Patch(':id/void')
  @HttpCode(HttpStatus.OK)
  async void(
    @Param('organizationId') orgId: string,
    @Param('id') id: string,
  ) {
    const data = await this.service.void(orgId, id);
    return SuccessHelper.createSuccessResponse(data, 'Assignment voided.');
  }

  @Delete(':id')
  @HttpCode(HttpStatus.OK)
  async delete(
    @Param('organizationId') orgId: string,
    @Param('id') id: string,
  ) {
    await this.service.delete(orgId, id);
    return SuccessHelper.createSuccessResponse(null, 'Assignment deleted.');
  }

  @Patch(':id/employee-sign')
  @HttpCode(HttpStatus.OK)
  async employeeSign(
    @Param('id') id: string,
    @Body() dto: EmployeeSignDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.service.employeeSign(id, dto.signature);
    return SuccessHelper.createSuccessResponse(data, 'Employee signature saved.');
  }
}
