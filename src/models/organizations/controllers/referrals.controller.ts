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
} from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import { JwtAuthGuard } from '../../../common/guards/jwt-auth.guard';
import { OrganizationRoleGuard } from '../../../common/guards/organization-role.guard';
import { LoggedInUser } from '../../../common/decorators/requests/logged-in-user.decorator';
import { SuccessHelper } from '../../../common/helpers/responses/success.helper';
import type { UserWithRolesInterface } from '../../../common/interfaces/user-with-roles.interface';
import { ReferralsService } from '../services/referrals.service';
import { ReferralMessagesService } from '../services/referral-messages.service';
import { CreateReferralDto } from '../dto/create-referral.dto';
import { QueryReferralDto } from '../dto/query-referral.dto';
import { UpdateReferralResponseDto } from '../dto/update-referral-response.dto';
import { AssignReferralDto } from '../dto/assign-referral.dto';
import { CreateReferralMessageDto } from '../dto/create-referral-message.dto';
import { QueryReferralMessagesDto } from '../dto/query-referral-messages.dto';

@Controller('v1/api/organization/:organizationId/referrals')
@UseGuards(JwtAuthGuard, OrganizationRoleGuard)
export class ReferralsController {
  constructor(
    private readonly referralsService: ReferralsService,
    private readonly referralMessagesService: ReferralMessagesService,
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
