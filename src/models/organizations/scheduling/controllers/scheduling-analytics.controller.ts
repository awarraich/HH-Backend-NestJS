import {
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Query,
  Request,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { JwtAuthGuard } from '../../../../common/guards/jwt-auth.guard';
import { OrganizationRoleGuard } from '../../../../common/guards/organization-role.guard';
import { Roles } from '../../../../common/decorators/roles.decorator';
import { SuccessHelper } from '../../../../common/helpers/responses/success.helper';
import { SchedulingAnalyticsService } from '../services/scheduling-analytics.service';
import {
  QueryAnalyticsDto,
  QueryHoursTrendDto,
  QueryUtilizationDto,
  QueryDayDetailDto,
  QueryResourceBrowseDto,
  QueryResourceAssignmentsDto,
  QueryDepartmentOverviewDto,
} from '../dto/query-analytics.dto';

interface RequestWithUser {
  user?: { userId?: string; sub?: string };
}

@Controller('v1/api/organizations/:organizationId/scheduling-analytics')
@UseGuards(JwtAuthGuard, OrganizationRoleGuard)
@Roles('OWNER', 'HR', 'MANAGER')
export class SchedulingAnalyticsController {
  constructor(private readonly analyticsService: SchedulingAnalyticsService) {}

  private resolveUserId(req: RequestWithUser): string {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    return userId;
  }

  @Get('kpis')
  @HttpCode(HttpStatus.OK)
  async getKpis(
    @Param('organizationId') organizationId: string,
    @Query() query: QueryAnalyticsDto,
    @Request() req: RequestWithUser,
  ) {
    const data = await this.analyticsService.getKpis(organizationId, query, this.resolveUserId(req));
    return SuccessHelper.createSuccessResponse(data);
  }

  @Get('calendar')
  @HttpCode(HttpStatus.OK)
  async getCalendar(
    @Param('organizationId') organizationId: string,
    @Query() query: QueryAnalyticsDto,
    @Request() req: RequestWithUser,
  ) {
    const data = await this.analyticsService.getCalendar(organizationId, query, this.resolveUserId(req));
    return SuccessHelper.createSuccessResponse(data);
  }

  @Get('shifts-by-day')
  @HttpCode(HttpStatus.OK)
  async getShiftsByDay(
    @Param('organizationId') organizationId: string,
    @Query() query: QueryAnalyticsDto,
    @Request() req: RequestWithUser,
  ) {
    const data = await this.analyticsService.getShiftsByDay(organizationId, query, this.resolveUserId(req));
    return SuccessHelper.createSuccessResponse(data);
  }

  @Get('assignments-by-role')
  @HttpCode(HttpStatus.OK)
  async getAssignmentsByRole(
    @Param('organizationId') organizationId: string,
    @Query() query: QueryAnalyticsDto,
    @Request() req: RequestWithUser,
  ) {
    const data = await this.analyticsService.getAssignmentsByRole(
      organizationId,
      query,
      this.resolveUserId(req),
    );
    return SuccessHelper.createSuccessResponse(data);
  }

  @Get('coverage-by-station')
  @HttpCode(HttpStatus.OK)
  async getCoverageByStation(
    @Param('organizationId') organizationId: string,
    @Query() query: QueryAnalyticsDto,
    @Request() req: RequestWithUser,
  ) {
    const data = await this.analyticsService.getCoverageByStation(
      organizationId,
      query,
      this.resolveUserId(req),
    );
    return SuccessHelper.createSuccessResponse(data);
  }

  @Get('utilization')
  @HttpCode(HttpStatus.OK)
  async getUtilization(
    @Param('organizationId') organizationId: string,
    @Query() query: QueryUtilizationDto,
    @Request() req: RequestWithUser,
  ) {
    const data = await this.analyticsService.getUtilization(organizationId, query, this.resolveUserId(req));
    return SuccessHelper.createSuccessResponse(data);
  }

  @Get('hours-trend')
  @HttpCode(HttpStatus.OK)
  async getHoursTrend(
    @Param('organizationId') organizationId: string,
    @Query() query: QueryHoursTrendDto,
    @Request() req: RequestWithUser,
  ) {
    const data = await this.analyticsService.getHoursTrend(organizationId, query, this.resolveUserId(req));
    return SuccessHelper.createSuccessResponse(data);
  }

  @Get('employee-load')
  @HttpCode(HttpStatus.OK)
  async getEmployeeLoad(
    @Param('organizationId') organizationId: string,
    @Query() query: QueryAnalyticsDto,
    @Request() req: RequestWithUser,
  ) {
    const data = await this.analyticsService.getEmployeeLoad(organizationId, query, this.resolveUserId(req));
    return SuccessHelper.createSuccessResponse(data);
  }

  @Get('day-detail')
  @HttpCode(HttpStatus.OK)
  async getDayDetail(
    @Param('organizationId') organizationId: string,
    @Query() query: QueryDayDetailDto,
    @Request() req: RequestWithUser,
  ) {
    const data = await this.analyticsService.getDayDetail(organizationId, query, this.resolveUserId(req));
    return SuccessHelper.createSuccessResponse(data);
  }

  // ───────────────────── resource browse ─────────────────────

  @Get('shifts-browse')
  @HttpCode(HttpStatus.OK)
  async getShiftsBrowse(
    @Param('organizationId') organizationId: string,
    @Query() query: QueryResourceBrowseDto,
    @Request() req: RequestWithUser,
  ) {
    const data = await this.analyticsService.getShiftsBrowse(organizationId, query, this.resolveUserId(req));
    return SuccessHelper.createSuccessResponse(data);
  }

  @Get('stations-browse')
  @HttpCode(HttpStatus.OK)
  async getStationsBrowse(
    @Param('organizationId') organizationId: string,
    @Query() query: QueryResourceBrowseDto,
    @Request() req: RequestWithUser,
  ) {
    const data = await this.analyticsService.getStationsBrowse(organizationId, query, this.resolveUserId(req));
    return SuccessHelper.createSuccessResponse(data);
  }

  @Get('rooms-browse')
  @HttpCode(HttpStatus.OK)
  async getRoomsBrowse(
    @Param('organizationId') organizationId: string,
    @Query() query: QueryResourceBrowseDto,
    @Request() req: RequestWithUser,
  ) {
    const data = await this.analyticsService.getRoomsBrowse(organizationId, query, this.resolveUserId(req));
    return SuccessHelper.createSuccessResponse(data);
  }

  @Get('beds-browse')
  @HttpCode(HttpStatus.OK)
  async getBedsBrowse(
    @Param('organizationId') organizationId: string,
    @Query() query: QueryResourceBrowseDto,
    @Request() req: RequestWithUser,
  ) {
    const data = await this.analyticsService.getBedsBrowse(organizationId, query, this.resolveUserId(req));
    return SuccessHelper.createSuccessResponse(data);
  }

  @Get('chairs-browse')
  @HttpCode(HttpStatus.OK)
  async getChairsBrowse(
    @Param('organizationId') organizationId: string,
    @Query() query: QueryResourceBrowseDto,
    @Request() req: RequestWithUser,
  ) {
    const data = await this.analyticsService.getChairsBrowse(organizationId, query, this.resolveUserId(req));
    return SuccessHelper.createSuccessResponse(data);
  }

  @Get('resource-assignments')
  @HttpCode(HttpStatus.OK)
  async getResourceAssignments(
    @Param('organizationId') organizationId: string,
    @Query() query: QueryResourceAssignmentsDto,
    @Request() req: RequestWithUser,
  ) {
    const data = await this.analyticsService.getResourceAssignments(
      organizationId,
      query,
      this.resolveUserId(req),
    );
    return SuccessHelper.createSuccessResponse(data);
  }

  // ───────────────────── department deep-dive ─────────────────────

  @Get('departments-browse')
  @HttpCode(HttpStatus.OK)
  async getDepartmentsBrowse(
    @Param('organizationId') organizationId: string,
    @Query() query: QueryAnalyticsDto,
    @Request() req: RequestWithUser,
  ) {
    const data = await this.analyticsService.getDepartmentsBrowse(
      organizationId,
      query,
      this.resolveUserId(req),
    );
    return SuccessHelper.createSuccessResponse(data);
  }

  @Get('department-overview')
  @HttpCode(HttpStatus.OK)
  async getDepartmentOverview(
    @Param('organizationId') organizationId: string,
    @Query() query: QueryDepartmentOverviewDto,
    @Request() req: RequestWithUser,
  ) {
    const data = await this.analyticsService.getDepartmentOverview(
      organizationId,
      query,
      this.resolveUserId(req),
    );
    return SuccessHelper.createSuccessResponse(data);
  }
}
