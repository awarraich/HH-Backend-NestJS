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
import { LabWorkstationService } from '../services/lab-workstation.service';
import { CreateLabWorkstationDto } from '../dto/create-lab-workstation.dto';
import { UpdateLabWorkstationDto } from '../dto/update-lab-workstation.dto';
import { QueryLabWorkstationDto } from '../dto/query-lab-workstation.dto';

type RequestWithUser = FastifyRequest & { user?: { userId?: string; sub?: string } };

@Controller('v1/api/organizations/:organizationId/departments/:departmentId/lab-workstations')
@UseGuards(JwtAuthGuard, OrganizationRoleGuard)
@Roles('OWNER', 'HR', 'MANAGER')
export class LabWorkstationsController {
  constructor(private readonly labWorkstationService: LabWorkstationService) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async findAll(
    @Param('organizationId') organizationId: string,
    @Param('departmentId') departmentId: string,
    @Query() query: QueryLabWorkstationDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const result = await this.labWorkstationService.findAll(organizationId, departmentId, query, userId);
    return SuccessHelper.createPaginatedResponse(result.data, result.total, result.page, result.limit);
  }

  @Get(':workstationId')
  @HttpCode(HttpStatus.OK)
  async findOne(
    @Param('organizationId') organizationId: string,
    @Param('departmentId') departmentId: string,
    @Param('workstationId') workstationId: string,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.labWorkstationService.findOne(organizationId, departmentId, workstationId, userId);
    return SuccessHelper.createSuccessResponse(data);
  }

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async create(
    @Param('organizationId') organizationId: string,
    @Param('departmentId') departmentId: string,
    @Body() dto: CreateLabWorkstationDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.labWorkstationService.create(organizationId, departmentId, dto, userId);
    return SuccessHelper.createSuccessResponse(data);
  }

  @Patch(':workstationId')
  @HttpCode(HttpStatus.OK)
  async update(
    @Param('organizationId') organizationId: string,
    @Param('departmentId') departmentId: string,
    @Param('workstationId') workstationId: string,
    @Body() dto: UpdateLabWorkstationDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.labWorkstationService.update(organizationId, departmentId, workstationId, dto, userId);
    return SuccessHelper.createSuccessResponse(data);
  }

  @Delete(':workstationId')
  @HttpCode(HttpStatus.OK)
  async remove(
    @Param('organizationId') organizationId: string,
    @Param('departmentId') departmentId: string,
    @Param('workstationId') workstationId: string,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    await this.labWorkstationService.remove(organizationId, departmentId, workstationId, userId);
    return SuccessHelper.createSuccessResponse(null, 'Lab workstation deleted');
  }
}
