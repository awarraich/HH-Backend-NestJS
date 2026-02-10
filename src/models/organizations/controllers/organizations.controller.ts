import {
  Controller,
  Get,
  Post,
  Put,
  Patch,
  Delete,
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
import { RolesGuard } from '../../../common/guards/roles.guard';
import { Roles } from '../../../common/decorators/roles.decorator';
import { LoggedInUser } from '../../../common/decorators/requests/logged-in-user.decorator';
import { SuccessHelper } from '../../../common/helpers/responses/success.helper';
import type { UserWithRolesInterface } from '../../../common/interfaces/user-with-roles.interface';
import { OrganizationsService } from '../services/organizations.service';
import { CreateOrganizationDto } from '../dto/create-organization.dto';
import { UpdateOrganizationDto } from '../dto/update-organization.dto';
import { QueryOrganizationDto } from '../dto/query-organization.dto';
import { CreateOrganizationProfileDto } from '../dto/create-organization-profile.dto';
import { UpdateOrganizationProfileDto } from '../dto/update-organization-profile.dto';
import { AssignOrganizationTypeDto } from '../dto/assign-organization-type.dto';
import { UpdateOrganizationPermissionDto } from '../dto/update-organization-permission.dto';

@Controller('v1/api/organization')
@UseGuards(JwtAuthGuard)
export class OrganizationsController {
  constructor(private readonly organizationsService: OrganizationsService) {}

  private getIpAddress(request: FastifyRequest): string {
    const forwarded = request.headers['x-forwarded-for'];
    if (forwarded) {
      return Array.isArray(forwarded) ? forwarded[0] : forwarded.split(',')[0];
    }
    return request.ip || request.socket.remoteAddress || 'unknown';
  }

  private getUserAgent(request: FastifyRequest): string {
    return request.headers['user-agent'] || 'unknown';
  }

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async create(
    @Body() createDto: CreateOrganizationDto,
    @LoggedInUser() user: UserWithRolesInterface,
    @Req() request: FastifyRequest,
  ) {
    const ipAddress = this.getIpAddress(request);
    const userAgent = this.getUserAgent(request);

    const result = await this.organizationsService.create(
      createDto,
      user.userId,
      ipAddress,
      userAgent,
    );

    return SuccessHelper.createSuccessResponse(result, 'Organization created successfully');
  }

  @Get()
  @HttpCode(HttpStatus.OK)
  @UseGuards(RolesGuard)
  @Roles('ADMIN')
  async findAll(@Query() queryDto: QueryOrganizationDto) {
    const result = await this.organizationsService.findAll(queryDto);

    return SuccessHelper.createPaginatedResponse(
      result.data,
      result.total,
      result.page,
      result.limit,
    );
  }

  @Get('my-organization')
  @HttpCode(HttpStatus.OK)
  async getMyOrganization(@LoggedInUser() user: UserWithRolesInterface) {
    const result = await this.organizationsService.findMyOrganization(user.userId);

    return SuccessHelper.createSuccessResponse(result);
  }

  @Get(':id')
  @HttpCode(HttpStatus.OK)
  async findOne(@Param('id') id: string) {
    const result = await this.organizationsService.findOne(id);

    return SuccessHelper.createSuccessResponse(result);
  }

  @Put(':id')
  @HttpCode(HttpStatus.OK)
  async update(
    @Param('id') id: string,
    @Body() updateDto: UpdateOrganizationDto,
    @LoggedInUser() user: UserWithRolesInterface,
    @Req() request: FastifyRequest,
  ) {
    const ipAddress = this.getIpAddress(request);
    const userAgent = this.getUserAgent(request);

    const result = await this.organizationsService.update(
      id,
      updateDto,
      user.userId,
      ipAddress,
      userAgent,
    );

    return SuccessHelper.createSuccessResponse(result, 'Organization updated successfully');
  }

  @Patch(':id')
  @HttpCode(HttpStatus.OK)
  async partialUpdate(
    @Param('id') id: string,
    @Body() updateDto: UpdateOrganizationDto,
    @LoggedInUser() user: UserWithRolesInterface,
    @Req() request: FastifyRequest,
  ) {
    const ipAddress = this.getIpAddress(request);
    const userAgent = this.getUserAgent(request);

    const result = await this.organizationsService.update(
      id,
      updateDto,
      user.userId,
      ipAddress,
      userAgent,
    );

    return SuccessHelper.createSuccessResponse(result, 'Organization updated successfully');
  }

  @Delete(':id')
  @HttpCode(HttpStatus.OK)
  async delete(
    @Param('id') id: string,
    @LoggedInUser() user: UserWithRolesInterface,
    @Req() request: FastifyRequest,
  ) {
    const ipAddress = this.getIpAddress(request);
    const userAgent = this.getUserAgent(request);

    await this.organizationsService.delete(id, user.userId, ipAddress, userAgent);

    return SuccessHelper.createSuccessResponse(null, 'Organization deleted successfully');
  }

  @Post(':id/profile')
  @HttpCode(HttpStatus.CREATED)
  async createProfile(
    @Param('id') id: string,
    @Body() createDto: CreateOrganizationProfileDto,
    @LoggedInUser() user: UserWithRolesInterface,
    @Req() request: FastifyRequest,
  ) {
    const ipAddress = this.getIpAddress(request);
    const userAgent = this.getUserAgent(request);

    const result = await this.organizationsService.createProfile(
      id,
      createDto,
      user.userId,
      ipAddress,
      userAgent,
    );

    return SuccessHelper.createSuccessResponse(
      result,
      'Organization profile created successfully',
    );
  }

  @Get(':id/profile')
  @HttpCode(HttpStatus.OK)
  async getProfile(@Param('id') id: string) {
    const organization = await this.organizationsService.findOne(id);

    return SuccessHelper.createSuccessResponse(organization.profile || null);
  }

  @Put(':id/profile')
  @HttpCode(HttpStatus.OK)
  async updateProfile(
    @Param('id') id: string,
    @Body() profileDto: UpdateOrganizationProfileDto,
    @LoggedInUser() user: UserWithRolesInterface,
    @Req() request: FastifyRequest,
  ) {
    const ipAddress = this.getIpAddress(request);
    const userAgent = this.getUserAgent(request);

    const result = await this.organizationsService.updateProfile(
      id,
      profileDto,
      user.userId,
      ipAddress,
      userAgent,
    );

    return SuccessHelper.createSuccessResponse(result, 'Organization profile updated successfully');
  }

  @Get(':id/types')
  @HttpCode(HttpStatus.OK)
  async getTypes(@Param('id') id: string) {
    const organization = await this.organizationsService.findOne(id);

    return SuccessHelper.createSuccessResponse(organization.types || []);
  }

  @Post('types/assign')
  @HttpCode(HttpStatus.OK)
  async assignType(
    @Body() assignDto: AssignOrganizationTypeDto,
    @LoggedInUser() user: UserWithRolesInterface,
    @Req() request: FastifyRequest,
  ) {
    const ipAddress = this.getIpAddress(request);
    const userAgent = this.getUserAgent(request);
  
    const result = await this.organizationsService.assignType(
      assignDto.organization_id,
      assignDto,
      user.userId,
      ipAddress,
      userAgent,
    );
  
    return SuccessHelper.createSuccessResponse(result, 'Organization type assigned successfully');
  }

  @Delete(':id/types/:typeId')
  @HttpCode(HttpStatus.OK)
  async removeType(
    @Param('id') id: string,
    @Param('typeId') typeId: string,
    @LoggedInUser() user: UserWithRolesInterface,
    @Req() request: FastifyRequest,
  ) {
    const ipAddress = this.getIpAddress(request);
    const userAgent = this.getUserAgent(request);

    await this.organizationsService.removeType(
      id,
      parseInt(typeId, 10),
      user.userId,
      ipAddress,
      userAgent,
    );

    return SuccessHelper.createSuccessResponse(null, 'Organization type removed successfully');
  }

  @Get(':id/permissions')
  @HttpCode(HttpStatus.OK)
  async getPermissions(@Param('id') id: string) {
    const result = await this.organizationsService.getPermissions(id);

    return SuccessHelper.createSuccessResponse(result);
  }

  @Put(':id/permissions')
  @HttpCode(HttpStatus.OK)
  async updatePermissions(
    @Param('id') id: string,
    @Body() permissionsDto: UpdateOrganizationPermissionDto | UpdateOrganizationPermissionDto[],
    @LoggedInUser() user: UserWithRolesInterface,
    @Req() request: FastifyRequest,
  ) {
    const ipAddress = this.getIpAddress(request);
    const userAgent = this.getUserAgent(request);

    const result = await this.organizationsService.updatePermissions(
      id,
      permissionsDto,
      user.userId,
      ipAddress,
      userAgent,
    );

    return SuccessHelper.createSuccessResponse(result, 'Organization permissions updated successfully');
  }
}
