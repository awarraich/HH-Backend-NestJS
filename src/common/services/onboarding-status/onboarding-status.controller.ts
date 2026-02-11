import { Controller, Get, UseGuards, HttpCode, HttpStatus } from '@nestjs/common';
import { JwtAuthGuard } from '../../guards/jwt-auth.guard';
import { LoggedInUser } from '../../decorators/requests/logged-in-user.decorator';
import { SuccessHelper } from '../../helpers/responses/success.helper';
import type { UserWithRolesInterface } from '../../interfaces/user-with-roles.interface';
import { OnboardingStatusService } from './onboarding-status.service';

@Controller('v1/api/onboarding')
@UseGuards(JwtAuthGuard)
export class OnboardingStatusController {
  constructor(
    private readonly onboardingStatusService: OnboardingStatusService,
  ) {}

  @Get('status')
  @HttpCode(HttpStatus.OK)
  async getOnboardingStatus(
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    const status = await this.onboardingStatusService.getOnboardingStatus(
      user.userId,
      user.roles,
    );

    return SuccessHelper.createSuccessResponse(status);
  }
}

