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
import { OrganizationRoleGuard } from '../../../common/guards/organization-role.guard';
import { Roles } from '../../../common/decorators/roles.decorator';
import { LoggedInUser } from '../../../common/decorators/requests/logged-in-user.decorator';
import { SuccessHelper } from '../../../common/helpers/responses/success.helper';
import type { UserWithRolesInterface } from '../../../common/interfaces/user-with-roles.interface';
import { EmployeesService } from '../services/employees.service';
import { CreateEmployeeDto } from '../dto/create-employee.dto';
import { UpdateEmployeeDto } from '../dto/update-employee.dto';
import { QueryEmployeeDto } from '../dto/query-employee.dto';
import { UpdateEmployeeRoleDto } from '../dto/update-employee-role.dto';
import { UpdateEmployeeStatusDto } from '../dto/update-employee-status.dto';
import { InviteEmployeeDto } from '../dto/invite-employee.dto';
import { UpdateEmployeeProfileDto } from '../dto/update-employee-profile.dto';

@Controller('v1/api/organization/:organizationId/employee')
@UseGuards(JwtAuthGuard, OrganizationRoleGuard)
export class EmployeesController {
  constructor(private readonly employeesService: EmployeesService) {}

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
  @Roles('OWNER', 'HR')
  async create(
    @Param('organizationId') organizationId: string,
    @Body() createDto: CreateEmployeeDto,
    @LoggedInUser() user: UserWithRolesInterface,
    @Req() request: FastifyRequest,
  ) {
    const ipAddress = this.getIpAddress(request);
    const userAgent = this.getUserAgent(request);

    const result = await this.employeesService.create(
      organizationId,
      createDto,
      user.userId,
      ipAddress,
      userAgent,
    );

    return SuccessHelper.createSuccessResponse(result, 'Employee added successfully');
  }

  @Get()
  @HttpCode(HttpStatus.OK)
  @Roles('OWNER', 'HR', 'ADMIN')
  async findAll(
    @Param('organizationId') organizationId: string,
    @Query() queryDto: QueryEmployeeDto,
  ) {
    const result = await this.employeesService.findAll(organizationId, queryDto);

    return SuccessHelper.createPaginatedResponse(
      result.data,
      result.total,
      result.page,
      result.limit,
    );
  }

  @Get(':id')
  @HttpCode(HttpStatus.OK)
  @Roles('OWNER', 'HR', 'ADMIN')
  async findOne(
    @Param('organizationId') organizationId: string,
    @Param('id') id: string,
  ) {
    const result = await this.employeesService.findOne(organizationId, id);

    return SuccessHelper.createSuccessResponse(result);
  }

  @Put(':id')
  @HttpCode(HttpStatus.OK)
  @Roles('OWNER', 'HR')
  async update(
    @Param('organizationId') organizationId: string,
    @Param('id') id: string,
    @Body() updateDto: UpdateEmployeeDto,
    @LoggedInUser() user: UserWithRolesInterface,
    @Req() request: FastifyRequest,
  ) {
    const ipAddress = this.getIpAddress(request);
    const userAgent = this.getUserAgent(request);

    const result = await this.employeesService.update(
      organizationId,
      id,
      updateDto,
      user.userId,
      ipAddress,
      userAgent,
    );

    return SuccessHelper.createSuccessResponse(result, 'Employee updated successfully');
  }

  @Patch(':id/role')
  @HttpCode(HttpStatus.OK)
  @Roles('OWNER', 'HR')
  async updateRole(
    @Param('organizationId') organizationId: string,
    @Param('id') id: string,
    @Body() roleDto: UpdateEmployeeRoleDto,
    @LoggedInUser() user: UserWithRolesInterface,
    @Req() request: FastifyRequest,
  ) {
    const ipAddress = this.getIpAddress(request);
    const userAgent = this.getUserAgent(request);

    const result = await this.employeesService.updateRole(
      organizationId,
      id,
      roleDto,
      user.userId,
      ipAddress,
      userAgent,
    );

    return SuccessHelper.createSuccessResponse(result, 'Employee role updated successfully');
  }

  @Patch(':id/status')
  @HttpCode(HttpStatus.OK)
  @Roles('OWNER', 'HR')
  async updateStatus(
    @Param('organizationId') organizationId: string,
    @Param('id') id: string,
    @Body() statusDto: UpdateEmployeeStatusDto,
    @LoggedInUser() user: UserWithRolesInterface,
    @Req() request: FastifyRequest,
  ) {
    const ipAddress = this.getIpAddress(request);
    const userAgent = this.getUserAgent(request);

    const result = await this.employeesService.updateStatus(
      organizationId,
      id,
      statusDto,
      user.userId,
      ipAddress,
      userAgent,
    );

    return SuccessHelper.createSuccessResponse(result, 'Employee status updated successfully');
  }

  @Delete(':id')
  @HttpCode(HttpStatus.OK)
  @Roles('OWNER', 'HR')
  async remove(
    @Param('organizationId') organizationId: string,
    @Param('id') id: string,
    @LoggedInUser() user: UserWithRolesInterface,
    @Req() request: FastifyRequest,
  ) {
    const ipAddress = this.getIpAddress(request);
    const userAgent = this.getUserAgent(request);

    await this.employeesService.remove(organizationId, id, user.userId, ipAddress, userAgent);

    return SuccessHelper.createSuccessResponse(null, 'Employee removed successfully');
  }

  @Get(':id/profile')
  @HttpCode(HttpStatus.OK)
  @Roles('OWNER', 'HR', 'ADMIN')
  async getProfile(
    @Param('organizationId') organizationId: string,
    @Param('id') id: string,
  ) {
    const result = await this.employeesService.getProfile(organizationId, id);

    return SuccessHelper.createSuccessResponse(result);
  }

  @Put(':id/profile')
  @HttpCode(HttpStatus.OK)
  async updateProfile(
    @Param('organizationId') organizationId: string,
    @Param('id') id: string,
    @Body() profileDto: UpdateEmployeeProfileDto,
    @LoggedInUser() user: UserWithRolesInterface,
    @Req() request: FastifyRequest,
  ) {
    const ipAddress = this.getIpAddress(request);
    const userAgent = this.getUserAgent(request);

    const result = await this.employeesService.updateProfile(
      organizationId,
      id,
      profileDto,
      user.userId,
      ipAddress,
      userAgent,
    );

    return SuccessHelper.createSuccessResponse(result, 'Employee profile updated successfully');
  }

  @Post(':id/invite')
  @HttpCode(HttpStatus.CREATED)
  @Roles('OWNER', 'HR')
  async invite(
    @Param('organizationId') organizationId: string,
    @Param('id') id: string,
    @Body() inviteDto: InviteEmployeeDto,
    @LoggedInUser() user: UserWithRolesInterface,
    @Req() request: FastifyRequest,
  ) {
    const ipAddress = this.getIpAddress(request);
    const userAgent = this.getUserAgent(request);

    // Note: The invite endpoint should use organizationId from params, not id
    // The id param here is not used, but kept for route consistency
    const result = await this.employeesService.invite(
      organizationId,
      inviteDto,
      user.userId,
      ipAddress,
      userAgent,
    );

    return SuccessHelper.createSuccessResponse(result, 'Employee invitation sent successfully');
  }

  @Post(':id/accept-invitation')
  @HttpCode(HttpStatus.OK)
  async acceptInvitation(
    @Param('organizationId') organizationId: string,
    @Param('id') id: string,
    @Body() body: { token: string },
    @LoggedInUser() user: UserWithRolesInterface,
    @Req() request: FastifyRequest,
  ) {
    const ipAddress = this.getIpAddress(request);
    const userAgent = this.getUserAgent(request);

    const result = await this.employeesService.acceptInvitation(
      body.token,
      user.userId,
      ipAddress,
      userAgent,
    );

    return SuccessHelper.createSuccessResponse(result, 'Invitation accepted successfully');
  }
}

