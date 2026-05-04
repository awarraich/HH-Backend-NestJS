import {
  Controller,
  Get,
  Post,
  Patch,
  Param,
  Body,
  HttpCode,
  HttpStatus,
  UseGuards,
} from '@nestjs/common';
import { JwtAuthGuard } from '../../../common/guards/jwt-auth.guard';
import { IntegrationAdminGuard } from '../guards/integration-admin.guard';
import { LoggedInUser } from '../../../common/decorators/requests/logged-in-user.decorator';
import { SuccessHelper } from '../../../common/helpers/responses/success.helper';
import type { UserWithRolesInterface } from '../../../common/interfaces/user-with-roles.interface';
import { OrganizationIntegrationService } from '../services/organization-integration.service';
import { EnableGoogleChatDto } from '../dto/enable-google-chat.dto';
import { UpdateGoogleChatConfigDto } from '../dto/update-google-chat-config.dto';

@Controller('v1/api/organizations/:organizationId/integrations/google-chat')
@UseGuards(JwtAuthGuard, IntegrationAdminGuard)
export class OrganizationIntegrationsController {
  constructor(
    private readonly integrationService: OrganizationIntegrationService,
  ) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async getStatus(@Param('organizationId') organizationId: string) {
    const integration = await this.integrationService.getStatus(organizationId);
    const install_url = this.integrationService.getInstallUrl();
    return SuccessHelper.createSuccessResponse({ integration, install_url });
  }

  @Post('enable')
  @HttpCode(HttpStatus.OK)
  async enable(
    @Param('organizationId') organizationId: string,
    @Body() dto: EnableGoogleChatDto,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    const integration = await this.integrationService.enable(
      organizationId,
      { workspaceDomain: dto.workspace_domain },
      { userId: user.userId, email: user.email },
    );
    return SuccessHelper.createSuccessResponse({ integration });
  }

  @Post('verify')
  @HttpCode(HttpStatus.OK)
  async verify(
    @Param('organizationId') organizationId: string,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    const integration = await this.integrationService.verify(organizationId, {
      userId: user.userId,
      email: user.email,
    });
    return SuccessHelper.createSuccessResponse({ integration });
  }

  @Patch('config')
  @HttpCode(HttpStatus.OK)
  async updateConfig(
    @Param('organizationId') organizationId: string,
    @Body() dto: UpdateGoogleChatConfigDto,
  ) {
    const integration = await this.integrationService.updateConfig(organizationId, dto);
    return SuccessHelper.createSuccessResponse({ integration });
  }

  @Post('disable')
  @HttpCode(HttpStatus.OK)
  async disable(@Param('organizationId') organizationId: string) {
    const integration = await this.integrationService.disable(organizationId);
    return SuccessHelper.createSuccessResponse({ integration });
  }

  @Get('employees')
  @HttpCode(HttpStatus.OK)
  async listEmployees(@Param('organizationId') organizationId: string) {
    const employees = await this.integrationService.listEmployees(organizationId);
    const summary = {
      connected: employees.filter((e) => e.status === 'connected').length,
      not_connected: employees.filter((e) => e.status === 'not_connected').length,
      email_only: employees.filter((e) => e.status === 'email_only').length,
      revoked: employees.filter((e) => e.status === 'revoked').length,
    };
    return SuccessHelper.createSuccessResponse({ employees, summary });
  }
}
