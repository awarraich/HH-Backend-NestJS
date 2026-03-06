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
import { HrDocumentTypeService } from '../services/hr-document-type.service';
import { CreateHrDocumentTypeDto } from '../dto/create-hr-document-type.dto';
import { UpdateHrDocumentTypeDto } from '../dto/update-hr-document-type.dto';
import { QueryHrDocumentTypeDto } from '../dto/query-hr-document-type.dto';

@Controller('v1/api/organizations/:organizationId/hr-document-types')
@UseGuards(JwtAuthGuard, OrganizationRoleGuard)
@Roles('OWNER', 'HR', 'MANAGER')
export class HrDocumentTypesController {
  constructor(private readonly hrDocumentTypeService: HrDocumentTypeService) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async findAll(
    @Param('organizationId') organizationId: string,
    @Query() query: QueryHrDocumentTypeDto,
    @Request() req: any,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    const result = await this.hrDocumentTypeService.findAll(
      organizationId,
      query,
      userId,
    );
    return SuccessHelper.createPaginatedResponse(
      result.data,
      result.total,
      result.page,
      result.limit,
    );
  }

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async create(
    @Param('organizationId') organizationId: string,
    @Body() dto: CreateHrDocumentTypeDto,
    @Request() req: any,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    const result = await this.hrDocumentTypeService.create(
      organizationId,
      dto,
      userId,
    );
    return SuccessHelper.createSuccessResponse(
      result,
      'HR document type created successfully',
    );
  }

  @Patch(':id')
  @HttpCode(HttpStatus.OK)
  async update(
    @Param('organizationId') organizationId: string,
    @Param('id') id: string,
    @Body() dto: UpdateHrDocumentTypeDto,
    @Request() req: any,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    const result = await this.hrDocumentTypeService.update(
      organizationId,
      id,
      dto,
      userId,
    );
    return SuccessHelper.createSuccessResponse(
      result,
      'HR document type updated successfully',
    );
  }

  @Delete(':id')
  @HttpCode(HttpStatus.OK)
  async remove(
    @Param('organizationId') organizationId: string,
    @Param('id') id: string,
    @Request() req: any,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    await this.hrDocumentTypeService.remove(organizationId, id, userId);
    return SuccessHelper.createSuccessResponse(
      null,
      'HR document type deactivated successfully',
    );
  }

  @Patch(':id/toggle-required')
  @HttpCode(HttpStatus.OK)
  async toggleRequired(
    @Param('organizationId') organizationId: string,
    @Param('id') id: string,
    @Request() req: any,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    const result = await this.hrDocumentTypeService.toggleRequired(
      organizationId,
      id,
      userId,
    );
    return SuccessHelper.createSuccessResponse(result);
  }
}
