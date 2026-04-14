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
  Logger,
} from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import { JwtAuthGuard } from '../../../../common/guards/jwt-auth.guard';
import { OrganizationRoleGuard } from '../../../../common/guards/organization-role.guard';
import { Roles } from '../../../../common/decorators/roles.decorator';
import { SuccessHelper } from '../../../../common/helpers/responses/success.helper';
import { DepartmentService } from '../services/department.service';
import { CreateDepartmentDto } from '../dto/create-department.dto';
import { UpdateDepartmentDto } from '../dto/update-department.dto';
import { QueryDepartmentDto } from '../dto/query-department.dto';

type RequestWithUser = FastifyRequest & { user?: { userId?: string; sub?: string } };

@Controller('v1/api/organizations/:organizationId/departments')
@UseGuards(JwtAuthGuard, OrganizationRoleGuard)
@Roles('OWNER', 'HR', 'MANAGER')
export class DepartmentsController {
  private readonly logger = new Logger('DepartmentsController'); // DEBUG
  constructor(private readonly departmentService: DepartmentService) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async findAll(
    @Param('organizationId') organizationId: string,
    @Query() query: QueryDepartmentDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const result = await this.departmentService.findAll(organizationId, query, userId);
    return SuccessHelper.createPaginatedResponse(
      result.data,
      result.total,
      result.page,
      result.limit,
    );
  }

  @Get(':departmentId')
  @HttpCode(HttpStatus.OK)
  async findOne(
    @Param('organizationId') organizationId: string,
    @Param('departmentId') departmentId: string,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.departmentService.findOne(organizationId, departmentId, userId);
    return SuccessHelper.createSuccessResponse(data);
  }

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async create(
    @Param('organizationId') organizationId: string,
    @Body() dto: CreateDepartmentDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.departmentService.create(organizationId, dto, userId);
    return SuccessHelper.createSuccessResponse(data);
  }

  @Patch(':departmentId')
  @HttpCode(HttpStatus.OK)
  async update(
    @Param('organizationId') organizationId: string,
    @Param('departmentId') departmentId: string,
    @Body() dto: UpdateDepartmentDto,
    @Request() req: RequestWithUser,
  ) {
    // DEBUG: Log incoming DTO to verify nested data arrives past validation
    this.logger.debug(`[UPDATE] PATCH /departments/${departmentId} — raw DTO keys: ${Object.keys(dto).join(', ')}`);
    this.logger.debug(`[UPDATE] stations: ${dto.stations ? JSON.stringify(dto.stations).slice(0, 500) : 'undefined'}`);
    this.logger.debug(`[UPDATE] rooms: ${dto.rooms ? JSON.stringify(dto.rooms).slice(0, 500) : 'undefined'}`);
    this.logger.debug(`[UPDATE] available_shifts: ${dto.available_shifts ? dto.available_shifts.length + ' items' : 'undefined'}`);
    this.logger.debug(`[UPDATE] staff: ${dto.staff ? dto.staff.length + ' items' : 'undefined'}`);
    this.logger.debug(`[UPDATE] field_zones: ${dto.field_zones ? dto.field_zones.length + ' items' : 'undefined'}`);
    this.logger.debug(`[UPDATE] fleet_vehicles: ${dto.fleet_vehicles ? dto.fleet_vehicles.length + ' items' : 'undefined'}`);
    this.logger.debug(`[UPDATE] lab_workstations: ${dto.lab_workstations ? dto.lab_workstations.length + ' items' : 'undefined'}`);
    this.logger.debug(`[UPDATE] layout_type: ${dto.layout_type ?? 'undefined'}`);

    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.departmentService.update(organizationId, departmentId, dto, userId);
    return SuccessHelper.createSuccessResponse(data);
  }

  @Delete(':departmentId')
  @HttpCode(HttpStatus.OK)
  async remove(
    @Param('organizationId') organizationId: string,
    @Param('departmentId') departmentId: string,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    await this.departmentService.remove(organizationId, departmentId, userId);
    return SuccessHelper.createSuccessResponse(null, 'Department deleted');
  }
}
