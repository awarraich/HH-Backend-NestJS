import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Body,
  Param,
  Query,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { JwtAuthGuard } from '../../../../common/guards/jwt-auth.guard';
import { LoggedInUser } from '../../../../common/decorators/requests/logged-in-user.decorator';
import { SuccessHelper } from '../../../../common/helpers/responses/success.helper';
import type { UserWithRolesInterface } from '../../../../common/interfaces/user-with-roles.interface';
import { CalendarEventService } from '../services/calendar-event.service';
import { AvailabilityRuleService } from '../services/availability-rule.service';
import { TimeOffRequestService } from '../services/time-off-request.service';
import { WorkPreferenceService } from '../services/work-preference.service';
import { CreateCalendarEventDto } from '../dto/create-calendar-event.dto';
import { UpdateCalendarEventDto } from '../dto/update-calendar-event.dto';
import { QueryCalendarEventDto } from '../dto/query-calendar-event.dto';
import { BulkUpsertAvailabilityDto } from '../dto/bulk-upsert-availability.dto';
import { CreateTimeOffRequestDto } from '../dto/create-time-off-request.dto';
import { QueryTimeOffRequestDto } from '../dto/query-time-off-request.dto';
import { UpdateWorkPreferenceDto } from '../dto/update-work-preference.dto';

@Controller('v1/api/employee/calendar')
@UseGuards(JwtAuthGuard)
export class EmployeeCalendarController {
  constructor(
    private readonly calendarEventService: CalendarEventService,
    private readonly availabilityRuleService: AvailabilityRuleService,
    private readonly timeOffRequestService: TimeOffRequestService,
    private readonly workPreferenceService: WorkPreferenceService,
  ) {}

  // ── Calendar Events ────────────────────────────────────────────────

  @Post('events')
  @HttpCode(HttpStatus.CREATED)
  async createEvent(
    @Body() dto: CreateCalendarEventDto,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    const result = await this.calendarEventService.create(user.userId, dto);
    return SuccessHelper.createSuccessResponse(result, 'Event created successfully');
  }

  @Get('events')
  @HttpCode(HttpStatus.OK)
  async findAllEvents(
    @Query() query: QueryCalendarEventDto,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    const result = await this.calendarEventService.findAll(user.userId, query);
    return SuccessHelper.createPaginatedResponse(
      result.data,
      result.total,
      result.page,
      result.limit,
    );
  }

  @Get('events/:id')
  @HttpCode(HttpStatus.OK)
  async findOneEvent(
    @Param('id') id: string,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    const result = await this.calendarEventService.findOne(user.userId, id);
    return SuccessHelper.createSuccessResponse(result);
  }

  @Put('events/:id')
  @HttpCode(HttpStatus.OK)
  async updateEvent(
    @Param('id') id: string,
    @Body() dto: UpdateCalendarEventDto,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    const result = await this.calendarEventService.update(user.userId, id, dto);
    return SuccessHelper.createSuccessResponse(result, 'Event updated successfully');
  }

  @Delete('events/:id')
  @HttpCode(HttpStatus.OK)
  async removeEvent(
    @Param('id') id: string,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    await this.calendarEventService.remove(user.userId, id);
    return SuccessHelper.createSuccessResponse(null, 'Event deleted successfully');
  }

  // ── Availability Rules ─────────────────────────────────────────────

  @Get('availability')
  @HttpCode(HttpStatus.OK)
  async getAvailability(
    @Query('organization_id') organizationId: string | undefined,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    const result = await this.availabilityRuleService.findByUser(
      user.userId,
      organizationId ?? null,
    );
    return SuccessHelper.createSuccessResponse(result);
  }

  @Put('availability')
  @HttpCode(HttpStatus.OK)
  async bulkUpsertAvailability(
    @Body() dto: BulkUpsertAvailabilityDto,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    const result = await this.availabilityRuleService.bulkUpsert(user.userId, dto);
    return SuccessHelper.createSuccessResponse(result, 'Availability saved successfully');
  }

  @Delete('availability/:id')
  @HttpCode(HttpStatus.OK)
  async removeAvailabilityRule(
    @Param('id') id: string,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    await this.availabilityRuleService.remove(user.userId, id);
    return SuccessHelper.createSuccessResponse(null, 'Availability rule deleted');
  }

  // ── Time-Off Requests ──────────────────────────────────────────────

  @Post('time-off')
  @HttpCode(HttpStatus.CREATED)
  async createTimeOff(
    @Body() dto: CreateTimeOffRequestDto,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    const result = await this.timeOffRequestService.create(user.userId, dto);
    return SuccessHelper.createSuccessResponse(result, 'Time-off request submitted');
  }

  @Get('time-off')
  @HttpCode(HttpStatus.OK)
  async findAllTimeOff(
    @Query() query: QueryTimeOffRequestDto,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    const result = await this.timeOffRequestService.findAll(user.userId, query);
    return SuccessHelper.createPaginatedResponse(
      result.data,
      result.total,
      result.page,
      result.limit,
    );
  }

  @Delete('time-off/:id')
  @HttpCode(HttpStatus.OK)
  async cancelTimeOff(
    @Param('id') id: string,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    await this.timeOffRequestService.cancel(user.userId, id);
    return SuccessHelper.createSuccessResponse(null, 'Time-off request cancelled');
  }

  // ── Work Preferences ──────────────────────────────────────────────

  @Get('preferences')
  @HttpCode(HttpStatus.OK)
  async getPreferences(
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    const result = await this.workPreferenceService.findOrCreate(user.userId);
    return SuccessHelper.createSuccessResponse(result);
  }

  @Put('preferences')
  @HttpCode(HttpStatus.OK)
  async updatePreferences(
    @Body() dto: UpdateWorkPreferenceDto,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    const result = await this.workPreferenceService.update(user.userId, dto);
    return SuccessHelper.createSuccessResponse(result, 'Preferences saved successfully');
  }
}
