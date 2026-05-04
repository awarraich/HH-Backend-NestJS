import { Controller, Get, Post, HttpCode, HttpStatus, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../../../common/guards/jwt-auth.guard';
import { LoggedInUser } from '../../../common/decorators/requests/logged-in-user.decorator';
import { SuccessHelper } from '../../../common/helpers/responses/success.helper';
import type { UserWithRolesInterface } from '../../../common/interfaces/user-with-roles.interface';
import { EmployeeNotificationsService } from '../services/employee-notifications.service';

@Controller('v1/api/me/notifications')
@UseGuards(JwtAuthGuard)
export class EmployeeNotificationsController {
  constructor(private readonly service: EmployeeNotificationsService) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async getStatus(@LoggedInUser() user: UserWithRolesInterface) {
    const data = await this.service.getStatus(user.userId);
    return SuccessHelper.createSuccessResponse(data);
  }

  @Post('chat/connect')
  @HttpCode(HttpStatus.OK)
  async connectChat(@LoggedInUser() user: UserWithRolesInterface) {
    const data = await this.service.connectChat(user.userId);
    return SuccessHelper.createSuccessResponse(data);
  }

  @Post('chat/disconnect')
  @HttpCode(HttpStatus.OK)
  async disconnectChat(@LoggedInUser() user: UserWithRolesInterface) {
    const data = await this.service.disconnectChat(user.userId);
    return SuccessHelper.createSuccessResponse(data);
  }
}
