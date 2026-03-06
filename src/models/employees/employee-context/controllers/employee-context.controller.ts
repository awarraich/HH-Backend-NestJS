import { Controller, Get, Query, UseGuards, HttpCode, HttpStatus } from '@nestjs/common';
import { JwtAuthGuard } from '../../../../common/guards/jwt-auth.guard';
import { LoggedInUser } from '../../../../common/decorators/requests/logged-in-user.decorator';
import { SuccessHelper } from '../../../../common/helpers/responses/success.helper';
import type { UserWithRolesInterface } from '../../../../common/interfaces/user-with-roles.interface';
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
  ) {
    const result = await this.employeeContextService.getContextByUserId(
      user.userId,
      currentOrganizationId ?? null,
    );
    return SuccessHelper.createSuccessResponse(result);
  }
}
