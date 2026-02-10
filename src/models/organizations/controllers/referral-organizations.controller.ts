import { Controller, Get, Query, UseGuards, HttpCode, HttpStatus } from '@nestjs/common';
import { JwtAuthGuard } from '../../../common/guards/jwt-auth.guard';
import { SuccessHelper } from '../../../common/helpers/responses/success.helper';
import { OrganizationsService } from '../services/organizations.service';
import { QueryReferralOrganizationsDto } from '../dto/query-referral-organizations.dto';

@Controller('v1/api/referrals')
@UseGuards(JwtAuthGuard)
export class ReferralOrganizationsController {
  constructor(private readonly organizationsService: OrganizationsService) {}

  @Get('organizations')
  @HttpCode(HttpStatus.OK)
  async listOrganizations(@Query() query: QueryReferralOrganizationsDto) {
    const data = await this.organizationsService.findForReferralSelection(query);
    return SuccessHelper.createSuccessResponse(data);
  }
}
