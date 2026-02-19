import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Body,
  Param,
  Query,
  UseGuards,
  Request,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { JwtAuthGuard } from '../../../../common/guards/jwt-auth.guard';
import { OrganizationRoleGuard } from '../../../../common/guards/organization-role.guard';
import { Roles } from '../../../../common/decorators/roles.decorator';
import { SuccessHelper } from '../../../../common/helpers/responses/success.helper';
import { OrganizationStaffService } from '../services/organization-staff.service';
import { CreateOrganizationStaffDto } from '../dto/create-organization-staff.dto';
import { QueryOrganizationStaffDto } from '../dto/query-organization-staff.dto';
import { UpdateOrganizationStaffDto } from '../dto/update-organization-staff.dto';
import { AssignStaffRoleDto } from '../dto/assign-staff-role.dto';

@Controller('v1/api/organizations/:organizationId/staff')
@UseGuards(JwtAuthGuard, OrganizationRoleGuard)
@Roles('OWNER', 'HR', 'MANAGER')
export class OrganizationStaffController {
  constructor(private readonly organizationStaffService: OrganizationStaffService) {}

  @Get('roles')
  @HttpCode(HttpStatus.OK)
  async getStaffRoles() {
    const roles = await this.organizationStaffService.findAllStaffRoles();
    return SuccessHelper.createSuccessResponse(roles);
  }

  @Post()
  @HttpCode(HttpStatus.CREATED)
  @Roles('OWNER')
  async createStaff(
    @Param('organizationId') organizationId: string,
    @Body() dto: CreateOrganizationStaffDto,
    @Request() req: any,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    const ipAddress = req.ip ?? req.connection?.remoteAddress;
    const userAgent = req.get?.('user-agent');
    const result = await this.organizationStaffService.createStaff(
      organizationId,
      dto,
      userId,
      ipAddress,
      userAgent,
    );
    return SuccessHelper.createSuccessResponse(result, 'Staff created. An email with temporary password has been sent.');
  }

  @Get()
  @HttpCode(HttpStatus.OK)
  async findAll(
    @Param('organizationId') organizationId: string,
    @Query() query: QueryOrganizationStaffDto,
    @Request() req: any,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    const result = await this.organizationStaffService.findAll(organizationId, query, userId);
    return SuccessHelper.createPaginatedResponse(result.data, result.total, result.page, result.limit);
  }

  @Get('users/:userId')
  @HttpCode(HttpStatus.OK)
  async findOne(
    @Param('organizationId') organizationId: string,
    @Param('userId') staffUserId: string,
    @Request() req: any,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    const staff = await this.organizationStaffService.findOneByUserId(organizationId, staffUserId, userId);
    return SuccessHelper.createSuccessResponse(staff);
  }

  @Patch('users/:userId')
  @HttpCode(HttpStatus.OK)
  async updateStaff(
    @Param('organizationId') organizationId: string,
    @Param('userId') staffUserId: string,
    @Body() dto: UpdateOrganizationStaffDto,
    @Request() req: any,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    const ipAddress = req.ip ?? req.connection?.remoteAddress;
    const userAgent = req.get?.('user-agent');
    const result = await this.organizationStaffService.updateStaff(
      organizationId,
      staffUserId,
      dto,
      userId,
      ipAddress,
      userAgent,
    );
    return SuccessHelper.createSuccessResponse(result);
  }

  @Post('users/:userId/roles')
  @HttpCode(HttpStatus.CREATED)
  async assignRole(
    @Param('organizationId') organizationId: string,
    @Param('userId') staffUserId: string,
    @Body() dto: AssignStaffRoleDto,
    @Request() req: any,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    const ipAddress = req.ip ?? req.connection?.remoteAddress;
    const userAgent = req.get?.('user-agent');
    const result = await this.organizationStaffService.assignRole(
      organizationId,
      staffUserId,
      dto.staff_role_id,
      userId,
      ipAddress,
      userAgent,
    );
    return SuccessHelper.createSuccessResponse(result, 'Role assigned.');
  }

  @Delete('users/:userId/roles/:staffRoleId')
  @HttpCode(HttpStatus.OK)
  async removeRole(
    @Param('organizationId') organizationId: string,
    @Param('userId') staffUserId: string,
    @Param('staffRoleId') staffRoleId: string,
    @Request() req: any,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    const ipAddress = req.ip ?? req.connection?.remoteAddress;
    const userAgent = req.get?.('user-agent');
    const result = await this.organizationStaffService.removeRole(
      organizationId,
      staffUserId,
      staffRoleId,
      userId,
      ipAddress,
      userAgent,
    );
    return SuccessHelper.createSuccessResponse(result);
  }
}
