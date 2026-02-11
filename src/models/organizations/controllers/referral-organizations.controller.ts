import {
  Controller,
  Get,
  Query,
  Param,
  UseGuards,
  HttpCode,
  HttpStatus,
  Res,
  NotFoundException,
} from '@nestjs/common';
import type { FastifyReply } from 'fastify';
import * as fs from 'fs';
import * as path from 'path';
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

  @Get('documents/files/:filename')
  @HttpCode(HttpStatus.OK)
  async serveReferralDocument(
    @Param('filename') filename: string,
    @Res() reply: FastifyReply,
  ) {
    const filePath = this.referralDocumentStorage.getLocalFilePath(filename);
    if (!filePath) throw new NotFoundException('File not found');
    const ext = path.extname(filename).toLowerCase();
    const contentType =
      { '.pdf': 'application/pdf', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png' }[
        ext
      ] || 'application/octet-stream';
    return reply
      .header('Content-Type', contentType)
      .header('Content-Disposition', `inline; filename="${filename}"`)
      .send(fs.createReadStream(filePath));
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
