import {
  Controller,
  Get,
  Post,
  Body,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { SuccessHelper } from '../../common/helpers/responses/success.helper';
import { AuthService } from '../services/auth.service';
import { AssignRoleDto } from '../dto/assign-role.dto';
import { LoggedInUser } from '../../common/decorators/requests/logged-in-user.decorator';
import type { UserWithRolesInterface } from '../../common/interfaces/user-with-roles.interface';

@Controller('v1/api/auth/roles')
@UseGuards(JwtAuthGuard)
export class RolesController {
  constructor(private readonly authService: AuthService) {}

  @Get('public')
  @HttpCode(HttpStatus.OK)
  async getPublicRoles() {
    const roles = await this.authService.getPublicRoles();
    return SuccessHelper.createSuccessResponse(roles);
  }

  @Post('assign')
  @HttpCode(HttpStatus.OK)
  async assignRole(
    @Body() assignRoleDto: AssignRoleDto,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    const result = await this.authService.assignRoleToUser(
      user.userId,
      assignRoleDto.role_id,
    );
    return SuccessHelper.createSuccessResponse(
      result,
      'Role assigned successfully',
    );
  }
}

