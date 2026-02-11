import {
  Controller,
  Get,
  Post,
  Patch,
  Body,
  Param,
  Query,
  UseGuards,
  HttpCode,
  HttpStatus,
  Req,
  BadRequestException,
} from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import { JwtAuthGuard } from '../../../common/guards/jwt-auth.guard';
import { OrganizationRoleGuard } from '../../../common/guards/organization-role.guard';
import { LoggedInUser } from '../../../common/decorators/requests/logged-in-user.decorator';
import { SuccessHelper } from '../../../common/helpers/responses/success.helper';
import type { UserWithRolesInterface } from '../../../common/interfaces/user-with-roles.interface';
import { ReferralsService } from '../services/referrals.service';
import { ReferralMessagesService } from '../services/referral-messages.service';
import { plainToInstance } from 'class-transformer';
import { validate } from 'class-validator';
import { CreateReferralDto } from '../dto/create-referral.dto';
import { QueryReferralDto } from '../dto/query-referral.dto';
import { UpdateReferralResponseDto } from '../dto/update-referral-response.dto';
import { AssignReferralDto } from '../dto/assign-referral.dto';
import { CreateReferralMessageDto } from '../dto/create-referral-message.dto';
import { QueryReferralMessagesDto } from '../dto/query-referral-messages.dto';
import { OrganizationsService } from '../services/organizations.service';
import { ReferralDocumentStorageService } from '../services/referral-document-storage.service';
import { QueryReferralOrganizationsDto } from '../dto/query-referral-organizations.dto';

@Controller('v1/api/organization/:organizationId/referrals')
@UseGuards(JwtAuthGuard, OrganizationRoleGuard)
export class ReferralsController {
  constructor(
    private readonly referralsService: ReferralsService,
    private readonly referralMessagesService: ReferralMessagesService,
    private readonly organizationsService: OrganizationsService,
    private readonly referralDocumentStorage: ReferralDocumentStorageService,
  ) {}

  private getIpAddress(request: FastifyRequest): string {
    const forwarded = request.headers['x-forwarded-for'];
    if (forwarded) {
      return Array.isArray(forwarded) ? forwarded[0] : forwarded.split(',')[0];
    }
    return request.ip || (request.socket as any)?.remoteAddress || 'unknown';
  }

  private getUserAgent(request: FastifyRequest): string {
    return (request.headers['user-agent'] as string) || 'unknown';
  }

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async create(
    @Param('organizationId') organizationId: string,
    @Body() createDto: CreateReferralDto,
    @LoggedInUser() user: UserWithRolesInterface,
    @Req() request: FastifyRequest,
  ) {
    const result = await this.referralsService.create(
      organizationId,
      user.userId,
      createDto,
      this.getIpAddress(request),
      this.getUserAgent(request),
    );
    return SuccessHelper.createSuccessResponse(result, 'Referral created successfully');
  }

  /**
   * Create referral with files in one request (multipart/form-data).
   * Form fields: "data" = JSON string of referral payload (without documents).
   * Form files: "documents" = one or more files (same field name for each).
   * With attachFieldsToBody: true, fields and files are on request.body; we read from there.
   */
  @Post('with-documents')
  @HttpCode(HttpStatus.CREATED)
  async createWithDocuments(
    @Param('organizationId') organizationId: string,
    @LoggedInUser() user: UserWithRolesInterface,
    @Req() request: FastifyRequest,
  ) {
    const multipartRequest = request as FastifyRequest & {
      isMultipart: () => boolean;
      body?: Record<
        string,
        | { value?: string; toBuffer?: () => Promise<Buffer>; filename?: string }
        | Array<{ toBuffer?: () => Promise<Buffer>; filename?: string }>
      >;
    };
    if (!multipartRequest.isMultipart?.()) {
      throw new BadRequestException('Content-Type must be multipart/form-data');
    }
    const documents: { file_name: string; file_url: string }[] = [];
    let payload: CreateReferralDto | null = null;

    // With attachFieldsToBody: true, plugin parses multipart and attaches to request.body
    const body = multipartRequest.body;
    if (body?.data != null) {
      const d = body.data as { value?: string | Record<string, unknown> };
      const value = d?.value;
      if (value != null) {
        if (typeof value === 'string' && value.trim().length > 0) {
          try {
            payload = JSON.parse(value) as CreateReferralDto;
          } catch {
            payload = null;
          }
        } else if (typeof value === 'object' && !Array.isArray(value)) {
          payload = value as unknown as CreateReferralDto;
        }
      }
    }
    if (body?.documents != null) {
      const docParts = Array.isArray(body.documents) ? body.documents : [body.documents];
      for (const part of docParts) {
        const p = part as { toBuffer?: () => Promise<Buffer>; filename?: string };
        if (p?.toBuffer && typeof p.toBuffer === 'function' && p.filename) {
          const buffer = await p.toBuffer();
          const result = await this.referralDocumentStorage.saveReferralDocument(
            buffer,
            p.filename,
          );
          documents.push(result);
        }
      }
    }

    if (!payload || typeof payload !== 'object') {
      throw new BadRequestException(
        'Missing or invalid "data" field. Send "data" as a form field (JSON string of referral payload).',
      );
    }
    payload.documents = documents;
    const createDto = plainToInstance(CreateReferralDto, payload);
    const errors = await validate(createDto, { whitelist: true, forbidNonWhitelisted: true });
    if (errors.length > 0) {
      const messages = errors.map((e) => Object.values(e.constraints ?? {})).flat();
      throw new BadRequestException(messages.join('; '));
    }
    const result = await this.referralsService.create(
      organizationId,
      user.userId,
      createDto,
      this.getIpAddress(request),
      this.getUserAgent(request),
    );
    return SuccessHelper.createSuccessResponse(result, 'Referral created successfully');
  }

  @Get()
  @HttpCode(HttpStatus.OK)
  async findAll(
    @Param('organizationId') organizationId: string,
    @Query() queryDto: QueryReferralDto,
    @LoggedInUser() user: UserWithRolesInterface,
    @Req() request: FastifyRequest,
  ) {
    const result = await this.referralsService.findAll(
      organizationId,
      queryDto,
      user.userId,
      this.getIpAddress(request),
      this.getUserAgent(request),
    );
    return SuccessHelper.createPaginatedResponse(
      result.data,
      result.total,
      result.page,
      result.limit,
    );
  }

  @Post('documents/upload')
  @HttpCode(HttpStatus.CREATED)
  async uploadReferralDocument(@Req() request: FastifyRequest) {
    const multipartRequest = request as FastifyRequest & {
      file: () => Promise<{ filename: string; toBuffer: () => Promise<Buffer> } | undefined>;
    };
    const data = await multipartRequest.file();
    if (!data) throw new BadRequestException('No file uploaded');
    const buffer = await data.toBuffer();
    const result = await this.referralDocumentStorage.saveReferralDocument(buffer, data.filename);
    return SuccessHelper.createSuccessResponse(result, 'File uploaded');
  }

  @Get('organizations')
  @HttpCode(HttpStatus.OK)
  async listOrganizationsForReferral(
    @Param('organizationId') organizationId: string,
    @Query() query: QueryReferralOrganizationsDto,
  ) {
    const data = await this.organizationsService.findForReferralSelection({
      ...query,
      exclude_organization_id: organizationId,
    });
    return SuccessHelper.createSuccessResponse(data);
  }

  @Get(':referralId/responses')
  @HttpCode(HttpStatus.OK)
  async getResponses(
    @Param('organizationId') organizationId: string,
    @Param('referralId') referralId: string,
    @LoggedInUser() user: UserWithRolesInterface,
    @Req() request: FastifyRequest,
  ) {
    const result = await this.referralsService.getResponses(
      organizationId,
      referralId,
      user.userId,
      this.getIpAddress(request),
      this.getUserAgent(request),
    );
    return SuccessHelper.createSuccessResponse(result);
  }

  @Get(':referralId/messages/threads')
  @HttpCode(HttpStatus.OK)
  async getThreads(
    @Param('organizationId') organizationId: string,
    @Param('referralId') referralId: string,
    @LoggedInUser() user: UserWithRolesInterface,
    @Req() request: FastifyRequest,
  ) {
    const result = await this.referralMessagesService.getThreads(
      organizationId,
      referralId,
      user.userId,
      this.getIpAddress(request),
      this.getUserAgent(request),
    );
    return SuccessHelper.createSuccessResponse(result);
  }

  @Get(':referralId/messages')
  @HttpCode(HttpStatus.OK)
  async getMessages(
    @Param('organizationId') organizationId: string,
    @Param('referralId') referralId: string,
    @Query() queryDto: QueryReferralMessagesDto,
    @LoggedInUser() user: UserWithRolesInterface,
    @Req() request: FastifyRequest,
  ) {
    const result = await this.referralMessagesService.getMessages(
      organizationId,
      referralId,
      queryDto,
      user.userId,
      this.getIpAddress(request),
      this.getUserAgent(request),
    );
    return SuccessHelper.createPaginatedResponse(
      result.data,
      result.total,
      result.page,
      result.limit,
    );
  }

  @Post(':referralId/messages/read')
  @HttpCode(HttpStatus.OK)
  async markRead(
    @Param('organizationId') organizationId: string,
    @Param('referralId') referralId: string,
    @LoggedInUser() user: UserWithRolesInterface,
    @Req() request: FastifyRequest,
  ) {
    await this.referralMessagesService.markRead(
      organizationId,
      referralId,
      user.userId,
      this.getIpAddress(request),
      this.getUserAgent(request),
    );
    return SuccessHelper.createSuccessResponse(null, 'Marked as read');
  }

  @Post(':referralId/messages')
  @HttpCode(HttpStatus.CREATED)
  async sendMessage(
    @Param('organizationId') organizationId: string,
    @Param('referralId') referralId: string,
    @Body() createDto: CreateReferralMessageDto,
    @LoggedInUser() user: UserWithRolesInterface,
    @Req() request: FastifyRequest,
  ) {
    const result = await this.referralMessagesService.send(
      organizationId,
      user.userId,
      referralId,
      createDto,
      this.getIpAddress(request),
      this.getUserAgent(request),
    );
    return SuccessHelper.createSuccessResponse(result, 'Message sent');
  }

  @Patch(':referralId/response')
  @HttpCode(HttpStatus.OK)
  async updateResponse(
    @Param('organizationId') organizationId: string,
    @Param('referralId') referralId: string,
    @Body() updateDto: UpdateReferralResponseDto,
    @LoggedInUser() user: UserWithRolesInterface,
    @Req() request: FastifyRequest,
  ) {
    const result = await this.referralsService.updateResponse(
      organizationId,
      referralId,
      updateDto,
      user.userId,
      this.getIpAddress(request),
      this.getUserAgent(request),
    );
    return SuccessHelper.createSuccessResponse(result);
  }

  @Post(':referralId/assign')
  @HttpCode(HttpStatus.OK)
  async assign(
    @Param('organizationId') organizationId: string,
    @Param('referralId') referralId: string,
    @Body() assignDto: AssignReferralDto,
    @LoggedInUser() user: UserWithRolesInterface,
    @Req() request: FastifyRequest,
  ) {
    const result = await this.referralsService.assignToOrganization(
      organizationId,
      referralId,
      assignDto,
      user.userId,
      this.getIpAddress(request),
      this.getUserAgent(request),
    );
    return SuccessHelper.createSuccessResponse(result, 'Referral assigned');
  }

  @Get(':referralId')
  @HttpCode(HttpStatus.OK)
  async findOne(
    @Param('organizationId') organizationId: string,
    @Param('referralId') referralId: string,
    @LoggedInUser() user: UserWithRolesInterface,
    @Req() request: FastifyRequest,
  ) {
    const result = await this.referralsService.findOne(
      organizationId,
      referralId,
      user.userId,
      this.getIpAddress(request),
      this.getUserAgent(request),
    );
    return SuccessHelper.createSuccessResponse(result);
  }
}
