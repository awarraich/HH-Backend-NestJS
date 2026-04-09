import {
  Controller,
  Get,
  Post,
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
import { DepartmentStaffService } from '../services/department-staff.service';
import { CreateDepartmentStaffDto } from '../dto/create-department-staff.dto';
import { UpdateDepartmentStaffDto } from '../dto/update-department-staff.dto';

type RequestWithUser = FastifyRequest & { user?: { userId?: string; sub?: string } };

@Controller('v1/api/organizations/:organizationId/departments/:departmentId/staff')
@UseGuards(JwtAuthGuard, OrganizationRoleGuard)
@Roles('OWNER', 'HR', 'MANAGER')
export class DepartmentStaffController {
  constructor(private readonly departmentStaffService: DepartmentStaffService) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async findAll(
    @Param('organizationId') organizationId: string,
    @Param('departmentId') departmentId: string,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.departmentStaffService.findAll(organizationId, departmentId, userId);
    return SuccessHelper.createSuccessResponse(data);
  }

  @Get(':staffId')
  @HttpCode(HttpStatus.OK)
  async findOne(
    @Param('organizationId') organizationId: string,
    @Param('departmentId') departmentId: string,
    @Param('staffId') staffId: string,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.departmentStaffService.findOne(organizationId, departmentId, staffId, userId);
    return SuccessHelper.createSuccessResponse(data);
  }

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async create(
    @Param('organizationId') organizationId: string,
    @Param('departmentId') departmentId: string,
    @Body() dto: CreateDepartmentStaffDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.departmentStaffService.create(organizationId, departmentId, dto, userId);
    return SuccessHelper.createSuccessResponse(data);
  }

  @Patch(':staffId')
  @HttpCode(HttpStatus.OK)
  async update(
    @Param('organizationId') organizationId: string,
    @Param('departmentId') departmentId: string,
    @Param('staffId') staffId: string,
    @Body() dto: UpdateDepartmentStaffDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.departmentStaffService.update(organizationId, departmentId, staffId, dto, userId);
    return SuccessHelper.createSuccessResponse(data);
  }

  @Delete(':staffId')
  @HttpCode(HttpStatus.OK)
  async remove(
    @Param('organizationId') organizationId: string,
    @Param('departmentId') departmentId: string,
    @Param('staffId') staffId: string,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    await this.departmentStaffService.remove(organizationId, departmentId, staffId, userId);
    return SuccessHelper.createSuccessResponse(null, 'Staff record deleted');
  }
}
