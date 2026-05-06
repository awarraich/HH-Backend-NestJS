import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Patch,
  Post,
  Req,
  Res,
} from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { SuccessHelper } from '../../../../common/helpers/responses/success.helper';
import { extractRequestSignatureMetadata } from '../../../../common/utils/extract-request-metadata';
import { CompetencyAssignmentV2Service } from '../services/competency-assignment-v2.service';
import { FillCompetencyFieldsByTokenDto } from '../dto/fill-competency-fields-v2.dto';

/**
 * Public token-gated competency fill endpoint for external employees.
 * Mirror of the offer-letter `/v1/api/offer-letter/fill/:token` flow.
 */
@Controller('v1/api/competency/fill')
export class CompetencyFillController {
  constructor(private readonly service: CompetencyAssignmentV2Service) {}

  @Get(':token')
  @HttpCode(HttpStatus.OK)
  async getContext(@Param('token') token: string) {
    const { assignment, roleAssignment } =
      await this.service.findByFillToken(token);
    const payload = {
      assignment,
      roleId: roleAssignment.role_id,
      recipientType: roleAssignment.recipient_type,
      roleName: roleAssignment.role?.name ?? null,
      submittedAt: roleAssignment.submitted_at,
      expiresAt: roleAssignment.fill_token_expires_at,
    };
    return SuccessHelper.createSuccessResponse(
      payload,
      'Competency document loaded.',
    );
  }

  @Patch(':token/fill')
  @HttpCode(HttpStatus.OK)
  async fill(
    @Param('token') token: string,
    @Body() dto: FillCompetencyFieldsByTokenDto,
    @Req() req: FastifyRequest,
  ) {
    const { assignment, roleAssignment } =
      await this.service.findByFillToken(token);
    const { ip, userAgent } = extractRequestSignatureMetadata(req);
    const data = await this.service.fillFields(
      assignment.id,
      roleAssignment.user_id,
      { ...dto, roleId: roleAssignment.role_id },
      {
        bypassMembershipCheck: true,
        requestMetadata: { ip, userAgent },
      },
    );
    return SuccessHelper.createSuccessResponse(data, 'Fields saved.');
  }

  @Post(':token/submit')
  @HttpCode(HttpStatus.OK)
  async submit(@Param('token') token: string) {
    const { assignment, roleAssignment } =
      await this.service.findByFillToken(token);
    const data = await this.service.submitRole(
      assignment.id,
      roleAssignment.user_id,
      roleAssignment.role_id,
      { bypassMembershipCheck: true },
    );
    return SuccessHelper.createSuccessResponse(data, 'Role submitted.');
  }

  /** Token-gated PDF stream so external recipients can render the doc. */
  @Get(':token/pdf')
  async viewPdf(
    @Param('token') token: string,
    @Res() reply: FastifyReply,
  ) {
    const { buffer, contentType, fileName } =
      await this.service.getPdfByToken(token);
    const safeName = fileName.replace(/["\\]/g, '_');
    return reply
      .header('Content-Type', contentType)
      .header('Content-Disposition', `inline; filename="${safeName}"`)
      .header('Accept-Ranges', 'bytes')
      .header('Cache-Control', 'private, max-age=60')
      .send(buffer);
  }
}
