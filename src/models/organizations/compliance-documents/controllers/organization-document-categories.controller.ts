import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Body,
  Param,
  UseGuards,
  HttpCode,
  HttpStatus,
  Request,
  UnauthorizedException,
} from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import { JwtAuthGuard } from '../../../../common/guards/jwt-auth.guard';
import { OrganizationRoleGuard } from '../../../../common/guards/organization-role.guard';
import { Roles } from '../../../../common/decorators/roles.decorator';
import { SuccessHelper } from '../../../../common/helpers/responses/success.helper';
import { OrganizationDocumentCategoriesService } from '../services/organization-document-categories.service';
import { CreateDocumentCategoryDto } from '../dto/create-document-category.dto';
import { UpdateDocumentCategoryDto } from '../dto/update-document-category.dto';

type RequestWithUser = FastifyRequest & { user?: { userId?: string; sub?: string } };

@Controller('v1/api/organizations/:organizationId/compliance/categories')
@UseGuards(JwtAuthGuard, OrganizationRoleGuard)
@Roles('OWNER', 'HR', 'MANAGER')
export class OrganizationDocumentCategoriesController {
  constructor(private readonly categoriesService: OrganizationDocumentCategoriesService) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async findAll(@Param('organizationId') organizationId: string) {
    const result = await this.categoriesService.findAll(organizationId);
    return SuccessHelper.createSuccessResponse(result);
  }

  @Get(':id')
  @HttpCode(HttpStatus.OK)
  async findOne(
    @Param('organizationId') organizationId: string,
    @Param('id') id: string,
  ) {
    const result = await this.categoriesService.findOne(organizationId, id);
    return SuccessHelper.createSuccessResponse(result);
  }

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async create(
    @Param('organizationId') organizationId: string,
    @Body() dto: CreateDocumentCategoryDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const result = await this.categoriesService.create(organizationId, dto, userId);
    return SuccessHelper.createSuccessResponse(result, 'Category created successfully');
  }

  @Patch(':id')
  @HttpCode(HttpStatus.OK)
  async update(
    @Param('organizationId') organizationId: string,
    @Param('id') id: string,
    @Body() dto: UpdateDocumentCategoryDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const result = await this.categoriesService.update(organizationId, id, dto, userId);
    return SuccessHelper.createSuccessResponse(result, 'Category updated successfully');
  }

  @Delete(':id')
  @HttpCode(HttpStatus.OK)
  async remove(
    @Param('organizationId') organizationId: string,
    @Param('id') id: string,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    await this.categoriesService.remove(organizationId, id, userId);
    return SuccessHelper.createSuccessResponse(null, 'Category deleted successfully');
  }
}
