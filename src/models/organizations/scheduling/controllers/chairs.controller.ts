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
import { ChairService } from '../services/chair.service';
import { CreateChairDto } from '../dto/create-chair.dto';
import { UpdateChairDto } from '../dto/update-chair.dto';
import { QueryChairDto } from '../dto/query-chair.dto';

type RequestWithUser = FastifyRequest & { user?: { userId?: string; sub?: string } };

@Controller(
  'v1/api/organizations/:organizationId/departments/:departmentId/stations/:stationId/rooms/:roomId/chairs',
)
@UseGuards(JwtAuthGuard, OrganizationRoleGuard)
@Roles('OWNER', 'HR', 'MANAGER')
export class ChairsController {
  constructor(private readonly chairService: ChairService) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async findAll(
    @Param('organizationId') organizationId: string,
    @Param('departmentId') departmentId: string,
    @Param('stationId') stationId: string,
    @Param('roomId') roomId: string,
    @Query() query: QueryChairDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const result = await this.chairService.findAll(
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

  @Get(':chairId')
  @HttpCode(HttpStatus.OK)
  async findOne(
    @Param('organizationId') organizationId: string,
    @Param('departmentId') departmentId: string,
    @Param('stationId') stationId: string,
    @Param('roomId') roomId: string,
    @Param('chairId') chairId: string,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.chairService.findOne(
      organizationId,
      departmentId,
      stationId,
      roomId,
      chairId,
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
    @Body() dto: CreateChairDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.chairService.create(
      organizationId,
      departmentId,
      stationId,
      roomId,
      dto,
      userId,
    );
    return SuccessHelper.createSuccessResponse(data);
  }

  @Patch(':chairId')
  @HttpCode(HttpStatus.OK)
  async update(
    @Param('organizationId') organizationId: string,
    @Param('departmentId') departmentId: string,
    @Param('stationId') stationId: string,
    @Param('roomId') roomId: string,
    @Param('chairId') chairId: string,
    @Body() dto: UpdateChairDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.chairService.update(
      organizationId,
      departmentId,
      stationId,
      roomId,
      chairId,
      dto,
      userId,
    );
    return SuccessHelper.createSuccessResponse(data);
  }

  @Delete(':chairId')
  @HttpCode(HttpStatus.OK)
  async remove(
    @Param('organizationId') organizationId: string,
    @Param('departmentId') departmentId: string,
    @Param('stationId') stationId: string,
    @Param('roomId') roomId: string,
    @Param('chairId') chairId: string,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    await this.chairService.remove(
      organizationId,
      departmentId,
      stationId,
      roomId,
      chairId,
      userId,
    );
    return SuccessHelper.createSuccessResponse(null, 'Chair deleted');
  }
}
