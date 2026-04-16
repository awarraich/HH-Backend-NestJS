import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Patch,
  Request,
  Res,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { JwtAuthGuard } from '../../../common/guards/jwt-auth.guard';
import { SuccessHelper } from '../../../common/helpers/responses/success.helper';
import { OfferLetterAssignmentService } from '../services/offer-letter-assignment.service';
import { FillOfferLetterFieldsDto } from '../dto/fill-offer-letter-fields.dto';

type RequestWithUser = FastifyRequest & {
  user?: { userId?: string; sub?: string };
};

/**
 * Authenticated user-scoped endpoints — lets the currently logged-in employee
 * or supervisor see the offer letters assigned to them and fill their share.
 */
@Controller('v1/api/me/offer-letter-assignments')
@UseGuards(JwtAuthGuard)
export class OfferLetterMyAssignmentsController {
  constructor(private readonly service: OfferLetterAssignmentService) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async listMine(@Request() req: RequestWithUser) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.service.findForUser(userId);
    return SuccessHelper.createSuccessResponse(data);
  }

  @Patch(':id/fill')
  @HttpCode(HttpStatus.OK)
  async fill(
    @Param('id') id: string,
    @Body() dto: FillOfferLetterFieldsDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.service.fillFields(id, userId, dto);
    return SuccessHelper.createSuccessResponse(data, 'Fields saved.');
  }

  /**
   * Stream the template PDF for an offer letter the caller is assigned to.
   * Scope-checked against the assignment's role rows, so employees and
   * supervisors can render the PDF without needing HR-level permissions.
   */
  @Get(':id/pdf')
  async viewPdf(
    @Param('id') id: string,
    @Request() req: RequestWithUser,
    @Res() reply: FastifyReply,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const { stream, contentType, fileName } = await this.service.getPdfForAssignee(id, userId);
    const safeName = encodeURIComponent(fileName).replace(/%20/g, '+');
    return reply
      .header('Content-Type', contentType)
      .header('Content-Disposition', `inline; filename="${safeName}"`)
      .send(stream);
  }
}
