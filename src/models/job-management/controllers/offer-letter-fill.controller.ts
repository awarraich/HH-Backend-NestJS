import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Res,
} from '@nestjs/common';
import type { FastifyReply } from 'fastify';
import { SuccessHelper } from '../../../common/helpers/responses/success.helper';
import { OfferLetterAssignmentService } from '../services/offer-letter-assignment.service';
import { FillOfferLetterByTokenDto } from '../dto/fill-offer-letter-by-token.dto';

/**
 * Public (no JWT) offer-letter fill endpoint for external employees.
 * Access is gated entirely by a one-time opaque `fill_token`.
 */
@Controller('v1/api/offer-letter/fill')
export class OfferLetterFillController {
  constructor(private readonly service: OfferLetterAssignmentService) {}

  @Get(':token')
  @HttpCode(HttpStatus.OK)
  async getContext(@Param('token') token: string) {
    const { assignment, roleAssignment } = await this.service.findByFillToken(token);
    const payload = {
      assignment,
      roleId: roleAssignment.role_id,
      recipientType: roleAssignment.recipient_type,
      roleName: roleAssignment.role?.name ?? null,
      completedAt: roleAssignment.completed_at,
      expiresAt: roleAssignment.fill_token_expires_at,
    };
    return SuccessHelper.createSuccessResponse(payload, 'Offer letter loaded.');
  }

  @Post(':token')
  @HttpCode(HttpStatus.OK)
  async submit(
    @Param('token') token: string,
    @Body() dto: FillOfferLetterByTokenDto,
  ) {
    const { assignment, roleAssignment } = await this.service.findByFillToken(token);
    const updated = await this.service.fillFields(
      assignment.id,
      roleAssignment.user_id,
      { roleId: roleAssignment.role_id, fields: dto.fields },
      { bypassRoleCheck: true },
    );
    return SuccessHelper.createSuccessResponse(updated, 'Fields saved.');
  }

  /** Token-gated PDF stream for the public fill page. */
  @Get(':token/pdf')
  async viewPdf(
    @Param('token') token: string,
    @Res() reply: FastifyReply,
  ) {
    const { stream, contentType, fileName } = await this.service.getPdfByToken(token);
    const safeName = encodeURIComponent(fileName).replace(/%20/g, '+');
    return reply
      .header('Content-Type', contentType)
      .header('Content-Disposition', `inline; filename="${safeName}"`)
      .send(stream);
  }
}
