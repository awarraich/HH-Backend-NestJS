import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Patch,
  Post,
  Query,
  Req,
  Request,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import { JwtAuthGuard } from '../../../../common/guards/jwt-auth.guard';
import { SuccessHelper } from '../../../../common/helpers/responses/success.helper';
import { extractRequestSignatureMetadata } from '../../../../common/utils/extract-request-metadata';
import { CompetencyAssignmentV2Service } from '../services/competency-assignment-v2.service';
import { FillCompetencyFieldsV2Dto } from '../dto/fill-competency-fields-v2.dto';
import { SubmitCompetencyRoleV2Dto } from '../dto/submit-competency-role-v2.dto';

type RequestWithUser = FastifyRequest & {
  user?: { userId?: string; sub?: string };
};

/**
 * Self-scoped (v2) competency fill endpoints. JWT-only; ownership is
 * enforced inside the service against `competency_assignment_roles`.
 */
@Controller('v1/api/me/document-workflow/v2/assignments')
@UseGuards(JwtAuthGuard)
export class MyCompetencyAssignmentsV2Controller {
  constructor(private readonly service: CompetencyAssignmentV2Service) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async listMine(@Request() req: RequestWithUser) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.service.findForUser(userId);
    return SuccessHelper.createSuccessResponse(data);
  }

  @Get(':id')
  @HttpCode(HttpStatus.OK)
  async findOneMine(
    @Param('id') id: string,
    @Query('roleId') roleId: string | undefined,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.service.findOneForUser(id, userId, roleId);
    return SuccessHelper.createSuccessResponse(data);
  }

  @Patch(':id/fill')
  @HttpCode(HttpStatus.OK)
  async fill(
    @Param('id') id: string,
    @Body() dto: FillCompetencyFieldsV2Dto,
    @Req() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const { ip, userAgent } = extractRequestSignatureMetadata(req);
    const data = await this.service.fillFields(id, userId, dto, {
      requestMetadata: { ip, userAgent },
    });
    return SuccessHelper.createSuccessResponse(data, 'Fields saved.');
  }

  @Post(':id/submit')
  @HttpCode(HttpStatus.OK)
  async submit(
    @Param('id') id: string,
    @Body() dto: SubmitCompetencyRoleV2Dto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.service.submitRole(id, userId, dto.roleId);
    return SuccessHelper.createSuccessResponse(data, 'Role submitted.');
  }
}
