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
import { BedService } from '../services/bed.service';
import { CreateBedDto } from '../dto/create-bed.dto';
import { UpdateBedDto } from '../dto/update-bed.dto';
import { QueryBedDto } from '../dto/query-bed.dto';

type RequestWithUser = FastifyRequest & { user?: { userId?: string; sub?: string } };

@Controller(
  'v1/api/organizations/:organizationId/departments/:departmentId/stations/:stationId/rooms/:roomId/beds',
)
@UseGuards(JwtAuthGuard, OrganizationRoleGuard)
@Roles('OWNER', 'HR', 'MANAGER')
export class BedsController {
  constructor(private readonly bedService: BedService) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async findAll(
    @Param('organizationId') organizationId: string,
    @Param('departmentId') departmentId: string,
    @Param('stationId') stationId: string,
    @Param('roomId') roomId: string,
    @Query() query: QueryBedDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const result = await this.bedService.findAll(
      organizationId,
      departmentId,
      stationId,
      roomId,
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

  @Get(':bedId')
  @HttpCode(HttpStatus.OK)
  async findOne(
    @Param('organizationId') organizationId: string,
    @Param('departmentId') departmentId: string,
    @Param('stationId') stationId: string,
    @Param('roomId') roomId: string,
    @Param('bedId') bedId: string,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.bedService.findOne(
      organizationId,
      departmentId,
      stationId,
      roomId,
      bedId,
      userId,
    );
    return SuccessHelper.createSuccessResponse(data);
  }

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async create(
    @Param('organizationId') organizationId: string,
    @Param('departmentId') departmentId: string,
    @Param('stationId') stationId: string,
    @Param('roomId') roomId: string,
    @Body() dto: CreateBedDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.bedService.create(
      organizationId,
      departmentId,
      stationId,
      roomId,
      dto,
      userId,
    );
    return SuccessHelper.createSuccessResponse(data);
  }

  @Patch(':bedId')
  @HttpCode(HttpStatus.OK)
  async update(
    @Param('organizationId') organizationId: string,
    @Param('departmentId') departmentId: string,
    @Param('stationId') stationId: string,
    @Param('roomId') roomId: string,
    @Param('bedId') bedId: string,
    @Body() dto: UpdateBedDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.bedService.update(
      organizationId,
      departmentId,
      stationId,
      roomId,
      bedId,
      dto,
      userId,
    );
    return SuccessHelper.createSuccessResponse(data);
  }

  @Delete(':bedId')
  @HttpCode(HttpStatus.OK)
  async remove(
    @Param('organizationId') organizationId: string,
    @Param('departmentId') departmentId: string,
    @Param('stationId') stationId: string,
    @Param('roomId') roomId: string,
    @Param('bedId') bedId: string,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    await this.bedService.remove(organizationId, departmentId, stationId, roomId, bedId, userId);
    return SuccessHelper.createSuccessResponse(null, 'Bed deleted');
  }
}
