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
import { StationService } from '../services/station.service';
import { CreateStationDto } from '../dto/create-station.dto';
import { UpdateStationDto } from '../dto/update-station.dto';
import { QueryStationDto } from '../dto/query-station.dto';

type RequestWithUser = FastifyRequest & { user?: { userId?: string; sub?: string } };

@Controller('v1/api/organizations/:organizationId/departments/:departmentId/stations')
@UseGuards(JwtAuthGuard, OrganizationRoleGuard)
@Roles('OWNER', 'HR', 'MANAGER')
export class StationsController {
  constructor(private readonly stationService: StationService) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async findAll(
    @Param('organizationId') organizationId: string,
    @Param('departmentId') departmentId: string,
    @Query() query: QueryStationDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const result = await this.stationService.findAll(organizationId, departmentId, query, userId);
    return SuccessHelper.createPaginatedResponse(
      result.data,
      result.total,
      result.page,
      result.limit,
    );
  }

  @Get(':stationId')
  @HttpCode(HttpStatus.OK)
  async findOne(
    @Param('organizationId') organizationId: string,
    @Param('departmentId') departmentId: string,
    @Param('stationId') stationId: string,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.stationService.findOne(organizationId, departmentId, stationId, userId);
    return SuccessHelper.createSuccessResponse(data);
  }

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async create(
    @Param('organizationId') organizationId: string,
    @Param('departmentId') departmentId: string,
    @Body() dto: CreateStationDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.stationService.create(organizationId, departmentId, dto, userId);
    return SuccessHelper.createSuccessResponse(data);
  }

  @Patch(':stationId')
  @HttpCode(HttpStatus.OK)
  async update(
    @Param('organizationId') organizationId: string,
    @Param('departmentId') departmentId: string,
    @Param('stationId') stationId: string,
    @Body() dto: UpdateStationDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.stationService.update(
      organizationId,
      departmentId,
      stationId,
      dto,
      userId,
    );
    return SuccessHelper.createSuccessResponse(data);
  }

  @Delete(':stationId')
  @HttpCode(HttpStatus.OK)
  async remove(
    @Param('organizationId') organizationId: string,
    @Param('departmentId') departmentId: string,
    @Param('stationId') stationId: string,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    await this.stationService.remove(organizationId, departmentId, stationId, userId);
    return SuccessHelper.createSuccessResponse(null, 'Station deleted');
  }
}
