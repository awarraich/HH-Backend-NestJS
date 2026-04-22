import {
  Controller,
  Get,
  Query,
  Param,
  UseGuards,
  HttpCode,
  HttpStatus,
  Res,
} from '@nestjs/common';
import type { FastifyReply } from 'fastify';
import { JwtAuthGuard } from '../../../common/guards/jwt-auth.guard';
import { LoggedInUser } from '../../../common/decorators/requests/logged-in-user.decorator';
import { SuccessHelper } from '../../../common/helpers/responses/success.helper';
import type { UserWithRolesInterface } from '../../../common/interfaces/user-with-roles.interface';
import { OrganizationsService } from '../services/organizations.service';
import { OrganizationRepository } from '../repositories/organization.repository';
import { ReferralDocumentStorageService } from '../services/referral-document-storage.service';
import { QueryReferralOrganizationsDto } from '../dto/query-referral-organizations.dto';

@Controller('v1/api/referrals')
@UseGuards(JwtAuthGuard)
export class ReferralOrganizationsController {
  constructor(
    private readonly organizationsService: OrganizationsService,
    private readonly organizationRepository: OrganizationRepository,
    private readonly referralDocumentStorage: ReferralDocumentStorageService,
  ) {}

  /** Preserves /referrals/documents/files/:filename — 302-redirects to a signed S3 GET URL. */
  @Get('documents/files/:filename')
  async serveReferralDocument(@Param('filename') filename: string, @Res() reply: FastifyReply) {
    const url = await this.referralDocumentStorage.getPresignedViewUrl(
      `referral-documents/${filename}`,
    );
    return reply.redirect(url, 302);
  }

  /**
   * Returns the signed S3 URL for a referral document as JSON.
   * Prefer this for opening the document in a new tab (window.open) — avoids
   * the tainted-origin problem you get when a CORS-mode fetch follows a 302
   * redirect to S3.
   */
  @Get('documents/:filename/file-url')
  @HttpCode(HttpStatus.OK)
  async getReferralDocumentFileUrl(@Param('filename') filename: string) {
    const url = await this.referralDocumentStorage.getPresignedViewUrl(
      `referral-documents/${filename}`,
    );
    return SuccessHelper.createSuccessResponse({ url });
  }

  @Get('organizations')
  @HttpCode(HttpStatus.OK)
  async listOrganizations(
    @Query() query: QueryReferralOrganizationsDto,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    const currentOrg = await this.organizationRepository.findByUserId(user.userId);
    const data = await this.organizationsService.findForReferralSelection({
      ...query,
      ...(currentOrg?.id && { exclude_organization_id: currentOrg.id }),
    });
    return SuccessHelper.createSuccessResponse(data);
  }
}
