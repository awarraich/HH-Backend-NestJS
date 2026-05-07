import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Request,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import { JwtAuthGuard } from '../../../../common/guards/jwt-auth.guard';
import { OrganizationRoleGuard } from '../../../../common/guards/organization-role.guard';
import { Roles } from '../../../../common/decorators/roles.decorator';
import { SuccessHelper } from '../../../../common/helpers/responses/success.helper';
import { CompetencyAssignmentV2Service } from '../services/competency-assignment-v2.service';
import { CreateCompetencyAssignmentV2Dto } from '../dto/create-competency-assignment-v2.dto';

type RequestWithUser = FastifyRequest & {
  user?: { userId?: string; sub?: string };
};

/**
 * Org-admin scope for the role-scoped (v2) competency fill flow. Coexists
 * with the legacy `/document-workflow/assignments` endpoints; nothing here
 * touches the existing routes or response shapes.
 */
@Controller(
  'v1/api/organizations/:organizationId/document-workflow/assignments-v2',
)
@UseGuards(JwtAuthGuard, OrganizationRoleGuard)
@Roles('OWNER', 'HR', 'MANAGER')
export class CompetencyAssignmentsV2Controller {
  constructor(private readonly service: CompetencyAssignmentV2Service) {}

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async create(
    @Param('organizationId') orgId: string,
    @Body() dto: CreateCompetencyAssignmentV2Dto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.service.create(orgId, dto, userId);
    return SuccessHelper.createSuccessResponse(
      data,
      'Workflow assigned and emails fanned out.',
    );
  }

  @Get(':id')
  @HttpCode(HttpStatus.OK)
  async findOne(
    @Param('organizationId') orgId: string,
    @Param('id') id: string,
  ) {
    const data = await this.service.findOneForOrg(orgId, id);
    return SuccessHelper.createSuccessResponse(data);
  }

  @Get('employee/:userId')
  @HttpCode(HttpStatus.OK)
  async findForEmployee(
    @Param('organizationId') orgId: string,
    @Param('userId') employeeUserId: string,
  ) {
    const data = await this.service.findForEmployee(orgId, employeeUserId);
    return SuccessHelper.createSuccessResponse(data);
  }
}
