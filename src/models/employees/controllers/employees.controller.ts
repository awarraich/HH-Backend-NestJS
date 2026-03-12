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
import { CreateEmployeeByEmailDto } from '../dto/create-employee-by-email.dto';
import { UpdateEmployeeDto } from '../dto/update-employee.dto';
import { QueryEmployeeDto } from '../dto/query-employee.dto';
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

  @Post('by-email')
  @HttpCode(HttpStatus.CREATED)
  @Roles('OWNER', 'HR')
  async createByEmail(
    @Param('organizationId') organizationId: string,
    @Body() dto: CreateEmployeeByEmailDto,
    @LoggedInUser() user: UserWithRolesInterface,
    @Req() request: FastifyRequest,
  ) {
    const ipAddress = this.getIpAddress(request);
    const userAgent = this.getUserAgent(request);
    const result = await this.employeesService.createByEmail(
      organizationId,
      dto,
      user.userId,
      ipAddress,
      userAgent,
    );
    const message =
      dto.authMethod === 'GOOGLE_SIGNIN'
        ? 'Employee created. An email with Google sign-in instructions has been sent.'
        : 'Employee created. An email with temporary password has been sent.';
    return SuccessHelper.createSuccessResponse(result, message);
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
  async findOne(@Param('organizationId') organizationId: string, @Param('id') id: string) {
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
  async getProfile(@Param('organizationId') organizationId: string, @Param('id') id: string) {
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
