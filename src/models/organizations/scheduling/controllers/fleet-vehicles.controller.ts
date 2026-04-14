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
import { FleetVehicleService } from '../services/fleet-vehicle.service';
import { CreateFleetVehicleDto } from '../dto/create-fleet-vehicle.dto';
import { UpdateFleetVehicleDto } from '../dto/update-fleet-vehicle.dto';
import { QueryFleetVehicleDto } from '../dto/query-fleet-vehicle.dto';

type RequestWithUser = FastifyRequest & { user?: { userId?: string; sub?: string } };

@Controller('v1/api/organizations/:organizationId/departments/:departmentId/fleet-vehicles')
@UseGuards(JwtAuthGuard, OrganizationRoleGuard)
@Roles('OWNER', 'HR', 'MANAGER')
export class FleetVehiclesController {
  constructor(private readonly fleetVehicleService: FleetVehicleService) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async findAll(
    @Param('organizationId') organizationId: string,
    @Param('departmentId') departmentId: string,
    @Query() query: QueryFleetVehicleDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const result = await this.fleetVehicleService.findAll(organizationId, departmentId, query, userId);
    return SuccessHelper.createPaginatedResponse(result.data, result.total, result.page, result.limit);
  }

  @Get(':vehicleId')
  @HttpCode(HttpStatus.OK)
  async findOne(
    @Param('organizationId') organizationId: string,
    @Param('departmentId') departmentId: string,
    @Param('vehicleId') vehicleId: string,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.fleetVehicleService.findOne(organizationId, departmentId, vehicleId, userId);
    return SuccessHelper.createSuccessResponse(data);
  }

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async create(
    @Param('organizationId') organizationId: string,
    @Param('departmentId') departmentId: string,
    @Body() dto: CreateFleetVehicleDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.fleetVehicleService.create(organizationId, departmentId, dto, userId);
    return SuccessHelper.createSuccessResponse(data);
  }

  @Patch(':vehicleId')
  @HttpCode(HttpStatus.OK)
  async update(
    @Param('organizationId') organizationId: string,
    @Param('departmentId') departmentId: string,
    @Param('vehicleId') vehicleId: string,
    @Body() dto: UpdateFleetVehicleDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.fleetVehicleService.update(organizationId, departmentId, vehicleId, dto, userId);
    return SuccessHelper.createSuccessResponse(data);
  }

  @Delete(':vehicleId')
  @HttpCode(HttpStatus.OK)
  async remove(
    @Param('organizationId') organizationId: string,
    @Param('departmentId') departmentId: string,
    @Param('vehicleId') vehicleId: string,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    await this.fleetVehicleService.remove(organizationId, departmentId, vehicleId, userId);
    return SuccessHelper.createSuccessResponse(null, 'Fleet vehicle deleted');
  }
}
