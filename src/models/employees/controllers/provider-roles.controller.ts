import { Controller, Get, Param, UseGuards, HttpCode, HttpStatus } from '@nestjs/common';
import { JwtAuthGuard } from '../../../common/guards/jwt-auth.guard';
import { OrganizationRoleGuard } from '../../../common/guards/organization-role.guard';
import { Roles } from '../../../common/decorators/roles.decorator';
import { SuccessHelper } from '../../../common/helpers/responses/success.helper';
import { ProviderRolesService } from '../services/provider-roles.service';
import { ProviderRoleSerializer } from '../serializers/provider-role.serializer';

@Controller('v1/api/organization/:organizationId/provider-roles')
@UseGuards(JwtAuthGuard, OrganizationRoleGuard)
export class ProviderRolesController {
  private readonly providerRoleSerializer = new ProviderRoleSerializer();

  constructor(private readonly providerRolesService: ProviderRolesService) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  @Roles('OWNER', 'HR', 'ADMIN')
  async findAll(@Param('organizationId') _organizationId: string): Promise<unknown> {
    const roles = await this.providerRolesService.findAll();
    const data = this.providerRoleSerializer.serializeMany(roles);
    return SuccessHelper.createSuccessResponse(data);
  }
}
