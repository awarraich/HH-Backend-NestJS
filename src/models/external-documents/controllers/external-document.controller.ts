import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  Query,
  UseGuards,
  HttpCode,
  HttpStatus,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtAuthGuard } from '../../../common/guards/jwt-auth.guard';
import { LoggedInUser } from '../../../common/decorators/requests/logged-in-user.decorator';
import type { UserWithRolesInterface } from '../../../common/interfaces/user-with-roles.interface';
import { SuccessHelper } from '../../../common/helpers/responses/success.helper';
import { ExternalDocumentService } from '../services/external-document.service';
import { SubmitExternalFieldsDto } from '../dto/submit-external-fields.dto';
import { RejectAssignmentDto } from '../dto/reject-assignment.dto';

@Controller('v1/api/documents')
@UseGuards(JwtAuthGuard)
export class ExternalDocumentController {
  constructor(private readonly service: ExternalDocumentService) {}

  /**
   * GET /v1/api/documents/my-assignments?userId=xxx
   *
   * Returns all templates assigned to this user with their role-based editable fields
   * and all filled values from all users.
   */
  @Get('my-assignments')
  @HttpCode(HttpStatus.OK)
  async getMyAssignments(@Query('userId') userId: string) {
    const data = await this.service.getMyAssignments(userId);
    return SuccessHelper.createSuccessResponse(data);
  }

  @Post(':templateId/submit')
  @HttpCode(HttpStatus.OK)
  async submitFields(
    @Param('templateId') templateId: string,
    @Body() dto: SubmitExternalFieldsDto,
  ) {
    const data = await this.service.submitFields(templateId, dto);
    return SuccessHelper.createSuccessResponse(data, 'Fields submitted successfully.');
  }

  // ─── Phase 2 lifecycle endpoints ───────────────────────────────
  // submit:   employee → template.requires_review must be true
  // approve:  admin (HR/manager/owner) → from `submitted`
  // reject:   admin → from `submitted`, with mandatory reason
  // reopen:   admin → from any terminal state, allows re-fill
  //
  // Org-level role authorization for approve/reject/reopen lives at
  // the route level in a future iteration; today the JWT guard alone
  // protects them. The service still verifies state preconditions so
  // an unprivileged user can't drive the lifecycle into an invalid
  // place even by hammering the endpoint.

  @Post('assignments/:assignmentId/submit')
  @HttpCode(HttpStatus.OK)
  async submitAssignment(
    @Param('assignmentId') assignmentId: string,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    if (!user?.userId) throw new UnauthorizedException('User ID not found');
    const data = await this.service.submitAssignment(assignmentId, user.userId);
    return SuccessHelper.createSuccessResponse(data, 'Assignment submitted for review.');
  }

  @Post('assignments/:assignmentId/approve')
  @HttpCode(HttpStatus.OK)
  async approveAssignment(
    @Param('assignmentId') assignmentId: string,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    if (!user?.userId) throw new UnauthorizedException('User ID not found');
    const data = await this.service.approveAssignment(assignmentId, user.userId);
    return SuccessHelper.createSuccessResponse(data, 'Assignment approved.');
  }

  @Post('assignments/:assignmentId/reject')
  @HttpCode(HttpStatus.OK)
  async rejectAssignment(
    @Param('assignmentId') assignmentId: string,
    @Body() dto: RejectAssignmentDto,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    if (!user?.userId) throw new UnauthorizedException('User ID not found');
    const data = await this.service.rejectAssignment(assignmentId, user.userId, dto.reason);
    return SuccessHelper.createSuccessResponse(data, 'Assignment rejected.');
  }

  @Post('assignments/:assignmentId/reopen')
  @HttpCode(HttpStatus.OK)
  async reopenAssignment(
    @Param('assignmentId') assignmentId: string,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    if (!user?.userId) throw new UnauthorizedException('User ID not found');
    const data = await this.service.reopenAssignment(assignmentId, user.userId);
    return SuccessHelper.createSuccessResponse(data, 'Assignment reopened.');
  }
}
