import {
  Body,
  Controller,
  Get,
  Param,
  Patch,
  Query,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { JwtAuthGuard } from '../../../../common/guards/jwt-auth.guard';
import { LoggedInUser } from '../../../../common/decorators/requests/logged-in-user.decorator';
import { SuccessHelper } from '../../../../common/helpers/responses/success.helper';
import type { UserWithRolesInterface } from '../../../../common/interfaces/user-with-roles.interface';
import { MyScheduledWorkService } from '../services/my-scheduled-work.service';
import { QueryMyScheduledWorkDto } from '../dto/query-my-scheduled-work.dto';
import { RespondMyScheduledWorkDto } from '../dto/respond-my-scheduled-work.dto';

/**
 * "My Scheduled Work" — every clinic appointment, field visit, transport trip
 * and pharmacy prescription the user is assigned to, across all their orgs.
 * Mirrors `MyScheduleController` (calendar events) and `MyShiftsController`
 * (shifts), but sources its rows from the polymorphic `scheduled_tasks` table.
 */
@Controller('v1/api/employee/my-scheduled-work')
@UseGuards(JwtAuthGuard)
export class MyScheduledWorkController {
  constructor(private readonly service: MyScheduledWorkService) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async findMine(
    @Query() query: QueryMyScheduledWorkDto,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    const result = await this.service.findMine(user.userId, query);
    return SuccessHelper.createPaginatedResponse(
      result.data,
      result.total,
      result.page,
      result.limit,
    );
  }

  @Patch(':assignmentId/respond')
  @HttpCode(HttpStatus.OK)
  async respond(
    @Param('assignmentId') assignmentId: string,
    @Body() dto: RespondMyScheduledWorkDto,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    const result = await this.service.respond(user.userId, assignmentId, dto.accept);
    return SuccessHelper.createSuccessResponse(
      result,
      dto.accept ? 'Assignment accepted' : 'Assignment declined',
    );
  }
}
