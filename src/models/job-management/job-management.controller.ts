import {
  Controller,
  Get,
  Patch,
  Delete,
  Body,
  Param,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { OrganizationRoleGuard } from '../../common/guards/organization-role.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { SuccessHelper } from '../../common/helpers/responses/success.helper';
import { JobManagementService } from './job-management.service';
import { UpdateJobPostingDto } from './dto/update-job-posting.dto';

@Controller('job-management')
export class JobManagementController {
  constructor(private readonly jobManagementService: JobManagementService) {}

  /* Create and list are registered in AppController so they work even if this module loads late */

  @Get('organization/:organizationId/job-postings/:id')
  @UseGuards(JwtAuthGuard, OrganizationRoleGuard)
  @Roles('OWNER', 'HR', 'ADMIN')
  @HttpCode(HttpStatus.OK)
  async findOne(
    @Param('organizationId') organizationId: string,
    @Param('id') id: string,
  ) {
    const result = await this.jobManagementService.findOne(organizationId, id);
    return SuccessHelper.createSuccessResponse(result);
  }

  @Patch('organization/:organizationId/job-postings/:id')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async update(
    @Param('organizationId') organizationId: string,
    @Param('id') id: string,
    @Body() updateDto: UpdateJobPostingDto,
  ) {
    const result = await this.jobManagementService.update(
      organizationId,
      id,
      updateDto,
    );
    return SuccessHelper.createSuccessResponse(result, 'Job posting updated');
  }

  @Delete('organization/:organizationId/job-postings/:id')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.NO_CONTENT)
  async remove(
    @Param('organizationId') organizationId: string,
    @Param('id') id: string,
  ) {
    await this.jobManagementService.remove(organizationId, id);
  }
}
