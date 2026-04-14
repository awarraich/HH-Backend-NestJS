import {
  Controller,
  Get,
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

/**
 * "My Schedule" — aggregates all events across every organization.
 * Never accepts or filters by organization_id.
 */
@Controller('v1/api/employee/my-schedule')
@UseGuards(JwtAuthGuard)
export class MyScheduleController {
  constructor(private readonly calendarEventService: CalendarEventService) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async getMySchedule(
    @Query('from_date') fromDate: string | undefined,
    @Query('to_date') toDate: string | undefined,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    const result = await this.calendarEventService.findMySchedule(
      user.userId,
      fromDate,
      toDate,
    );
    return SuccessHelper.createSuccessResponse(result);
  }
}
