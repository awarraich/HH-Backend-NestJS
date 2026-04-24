import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Put,
  Query,
  UseGuards,
} from '@nestjs/common';
import { JwtAuthGuard } from '../../../../common/guards/jwt-auth.guard';
import { LoggedInUser } from '../../../../common/decorators/requests/logged-in-user.decorator';
import { SuccessHelper } from '../../../../common/helpers/responses/success.helper';
import type { UserWithRolesInterface } from '../../../../common/interfaces/user-with-roles.interface';
import { UpdateEmployeeProfileDto } from '../../dto/update-employee-profile.dto';
import { EmployeeContextService } from '../services/employee-context.service';

@Controller('v1/api/employee')
@UseGuards(JwtAuthGuard)
export class EmployeeContextController {
  constructor(private readonly employeeContextService: EmployeeContextService) {}

  @Get('context')
  @HttpCode(HttpStatus.OK)
  async getContext(
    @Query('currentOrganizationId') currentOrganizationId: string | undefined,
    @LoggedInUser() user: UserWithRolesInterface,
  ): Promise<unknown> {
    const result = await this.employeeContextService.getContextByUserId(
      user.userId,
      currentOrganizationId ?? null,
      user.roles,
    );
    return SuccessHelper.createSuccessResponse(result);
  }

  /**
   * Update the authenticated user's profile when they aren't linked to any
   * organization ("independent employee"). Org-employee profiles still go
   * through `PUT /v1/api/organization/:orgId/employee/:employeeId/profile`.
   */
  @Put('profile')
  @HttpCode(HttpStatus.OK)
  async updateMyProfile(
    @Body() dto: UpdateEmployeeProfileDto,
    @LoggedInUser() user: UserWithRolesInterface,
  ): Promise<unknown> {
    const result = await this.employeeContextService.updateIndependentProfile(
      user.userId,
      user.roles,
      dto,
    );
    return SuccessHelper.createSuccessResponse(result, 'Employee profile updated successfully');
  }
}
