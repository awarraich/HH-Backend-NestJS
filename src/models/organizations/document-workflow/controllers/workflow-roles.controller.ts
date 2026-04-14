import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Body,
  Param,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { JwtAuthGuard } from '../../../../common/guards/jwt-auth.guard';
import { OrganizationRoleGuard } from '../../../../common/guards/organization-role.guard';
import { Roles } from '../../../../common/decorators/roles.decorator';
import { SuccessHelper } from '../../../../common/helpers/responses/success.helper';
import { WorkflowRolesService } from '../services/workflow-roles.service';
import { CreateWorkflowRoleDto } from '../dto/create-workflow-role.dto';
import { UpdateWorkflowRoleDto } from '../dto/update-workflow-role.dto';

@Controller('v1/api/organizations/:organizationId/document-workflow/roles')
@UseGuards(JwtAuthGuard, OrganizationRoleGuard)
export class WorkflowRolesController {
  constructor(private readonly service: WorkflowRolesService) {}

  // Any authenticated user can list roles (includes defaults)
  @Get()
  @Roles()
  @HttpCode(HttpStatus.OK)
  async findAll(@Param('organizationId') orgId: string) {
    const data = await this.service.findAll(orgId);
    return SuccessHelper.createSuccessResponse(data);
  }

  // Any authenticated user can view a role
  @Get(':id')
  @Roles()
  @HttpCode(HttpStatus.OK)
  async findOne(
    @Param('organizationId') orgId: string,
    @Param('id') id: string,
  ) {
    const data = await this.service.findOne(orgId, id);
    return SuccessHelper.createSuccessResponse(data);
  }

  @Post()
  @Roles('OWNER', 'HR', 'MANAGER')
  @HttpCode(HttpStatus.CREATED)
  async create(
    @Param('organizationId') orgId: string,
    @Body() dto: CreateWorkflowRoleDto,
  ) {
    const data = await this.service.create(orgId, dto);
    return SuccessHelper.createSuccessResponse(data, 'Workflow role created.');
  }

  @Patch(':id')
  @Roles('OWNER', 'HR', 'MANAGER')
  @HttpCode(HttpStatus.OK)
  async update(
    @Param('organizationId') orgId: string,
    @Param('id') id: string,
    @Body() dto: UpdateWorkflowRoleDto,
  ) {
    const data = await this.service.update(orgId, id, dto);
    return SuccessHelper.createSuccessResponse(data, 'Workflow role updated.');
  }

  @Delete(':id')
  @Roles('OWNER', 'HR', 'MANAGER')
  @HttpCode(HttpStatus.OK)
  async delete(
    @Param('organizationId') orgId: string,
    @Param('id') id: string,
  ) {
    await this.service.delete(orgId, id);
    return SuccessHelper.createSuccessResponse(null, 'Workflow role deleted.');
  }
}
