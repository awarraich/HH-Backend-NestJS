import {
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Query,
  Request,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import { JwtAuthGuard } from '../../../../common/guards/jwt-auth.guard';
import { SuccessHelper } from '../../../../common/helpers/responses/success.helper';
import { AssignmentsService } from '../services/assignments.service';

type RequestWithUser = FastifyRequest & {
  user?: { userId?: string; sub?: string };
};

/**
 * User-scoped document workflow endpoints. Lets the authenticated employee
 * see their own assignments without needing org-admin privileges (the
 * org-scoped controller is HR/Manager/Owner-only). Powers the "Document
 * Workflows" panel on the employee HR File / portal Documents tab.
 */
@Controller('v1/api/me/document-workflow')
@UseGuards(JwtAuthGuard)
export class MyDocumentWorkflowAssignmentsController {
  constructor(private readonly service: AssignmentsService) {}

  /**
   * Returns competency assignments where the caller is either the
   * supervisor or appears on a template role. When `organization_id` is
   * provided the result is filtered to that org; otherwise every org the
   * user has assignments in is included.
   */
  @Get('assignments')
  @HttpCode(HttpStatus.OK)
  async getMine(
    @Request() req: RequestWithUser,
    @Query('organization_id') organizationId?: string,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.service.getForEmployee(organizationId, userId);
    return SuccessHelper.createSuccessResponse(data);
  }
}
