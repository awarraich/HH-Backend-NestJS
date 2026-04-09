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
import { ZoneService } from '../services/zone.service';
import { CreateZoneDto } from '../dto/create-zone.dto';
import { UpdateZoneDto } from '../dto/update-zone.dto';
import { QueryZoneDto } from '../dto/query-zone.dto';

type RequestWithUser = FastifyRequest & { user?: { userId?: string; sub?: string } };

@Controller('v1/api/organizations/:organizationId/departments/:departmentId/zones')
@UseGuards(JwtAuthGuard, OrganizationRoleGuard)
@Roles('OWNER', 'HR', 'MANAGER')
export class ZonesController {
  constructor(private readonly zoneService: ZoneService) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async findAll(
    @Param('organizationId') organizationId: string,
    @Param('departmentId') departmentId: string,
    @Query() query: QueryZoneDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const result = await this.zoneService.findAll(organizationId, departmentId, query, userId);
    return SuccessHelper.createPaginatedResponse(result.data, result.total, result.page, result.limit);
  }

  @Get(':zoneId')
  @HttpCode(HttpStatus.OK)
  async findOne(
    @Param('organizationId') organizationId: string,
    @Param('departmentId') departmentId: string,
    @Param('zoneId') zoneId: string,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.zoneService.findOne(organizationId, departmentId, zoneId, userId);
    return SuccessHelper.createSuccessResponse(data);
  }

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async create(
    @Param('organizationId') organizationId: string,
    @Param('departmentId') departmentId: string,
    @Body() dto: CreateZoneDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.zoneService.create(organizationId, departmentId, dto, userId);
    return SuccessHelper.createSuccessResponse(data);
  }

  @Patch(':zoneId')
  @HttpCode(HttpStatus.OK)
  async update(
    @Param('organizationId') organizationId: string,
    @Param('departmentId') departmentId: string,
    @Param('zoneId') zoneId: string,
    @Body() dto: UpdateZoneDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.zoneService.update(organizationId, departmentId, zoneId, dto, userId);
    return SuccessHelper.createSuccessResponse(data);
  }

  @Delete(':zoneId')
  @HttpCode(HttpStatus.OK)
  async remove(
    @Param('organizationId') organizationId: string,
    @Param('departmentId') departmentId: string,
    @Param('zoneId') zoneId: string,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    await this.zoneService.remove(organizationId, departmentId, zoneId, userId);
    return SuccessHelper.createSuccessResponse(null, 'Zone deleted');
  }
}
