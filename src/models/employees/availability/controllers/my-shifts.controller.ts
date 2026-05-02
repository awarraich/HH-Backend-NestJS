import {
  Controller,
  Get,
  Patch,
  Param,
  Query,
  Body,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { JwtAuthGuard } from '../../../../common/guards/jwt-auth.guard';
import { LoggedInUser } from '../../../../common/decorators/requests/logged-in-user.decorator';
import { SuccessHelper } from '../../../../common/helpers/responses/success.helper';
import type { UserWithRolesInterface } from '../../../../common/interfaces/user-with-roles.interface';
import { MyShiftsService } from '../services/my-shifts.service';
import { QueryMyShiftsDto } from '../dto/query-my-shifts.dto';
import { RespondMyShiftDto } from '../dto/respond-my-shift.dto';

/**
 * Self-serve shift inbox for the logged-in employee. Returns rows from
 * `employee_shifts` joined with `shifts` for any Employee record that
 * belongs to this user (across all orgs they're hired into). Accept /
 * decline writes the assignment's `status` so the org-side scheduler
 * sees the response.
 */
@Controller('v1/api/employee/my-shifts')
@UseGuards(JwtAuthGuard)
export class MyShiftsController {
  constructor(private readonly myShiftsService: MyShiftsService) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async list(
    @Query() query: QueryMyShiftsDto,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    const result = await this.myShiftsService.findMine(user.userId, query);
    return SuccessHelper.createPaginatedResponse(
      result.data,
      result.total,
      result.page,
      result.limit,
    );
  }

  @Patch(':id/respond')
  @HttpCode(HttpStatus.OK)
  async respond(
    @Param('id') id: string,
    @Body() dto: RespondMyShiftDto,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    const result = await this.myShiftsService.respond(user.userId, id, dto.accept);
    return SuccessHelper.createSuccessResponse(
      result,
      dto.accept ? 'Shift accepted' : 'Shift declined',
    );
  }
}
