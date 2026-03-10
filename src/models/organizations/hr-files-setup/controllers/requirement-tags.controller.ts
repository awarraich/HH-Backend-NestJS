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
  HttpCode,
  HttpStatus,
  Request,
  UnauthorizedException,
} from '@nestjs/common';
import type { FastifyRequest } from 'fastify';

type RequestWithUser = FastifyRequest & { user?: { userId?: string; sub?: string } };
import { JwtAuthGuard } from '../../../../common/guards/jwt-auth.guard';
import { OrganizationRoleGuard } from '../../../../common/guards/organization-role.guard';
import { Roles } from '../../../../common/decorators/roles.decorator';
import { SuccessHelper } from '../../../../common/helpers/responses/success.helper';
import { RequirementTagService } from '../services/requirement-tag.service';
import { CreateRequirementTagDto } from '../dto/create-requirement-tag.dto';
import { UpdateRequirementTagDto } from '../dto/update-requirement-tag.dto';
import { QueryRequirementTagDto } from '../dto/query-requirement-tag.dto';

@Controller('v1/api/organizations/:organizationId/requirement-tags')
@UseGuards(JwtAuthGuard, OrganizationRoleGuard)
@Roles('OWNER', 'HR', 'MANAGER')
export class RequirementTagsController {
  constructor(private readonly requirementTagService: RequirementTagService) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async findAll(
    @Param('organizationId') organizationId: string,
    @Query() query: QueryRequirementTagDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const result = await this.requirementTagService.findAll(organizationId, query, userId);
    return SuccessHelper.createPaginatedResponse(
      result.data,
      result.total,
      result.page,
      result.limit,
    );
  }

  @Get(':requirementTagId')
  @HttpCode(HttpStatus.OK)
  async findOne(
    @Param('organizationId') organizationId: string,
    @Param('requirementTagId') requirementTagId: string,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const result = await this.requirementTagService.findOne(
      organizationId,
      requirementTagId,
      userId,
    );
    return SuccessHelper.createSuccessResponse(result);
  }

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async create(
    @Param('organizationId') organizationId: string,
    @Body() dto: CreateRequirementTagDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const result = await this.requirementTagService.create(organizationId, dto, userId);
    return SuccessHelper.createSuccessResponse(result, 'Requirement tag created successfully');
  }

  @Patch(':requirementTagId')
  @HttpCode(HttpStatus.OK)
  async update(
    @Param('organizationId') organizationId: string,
    @Param('requirementTagId') requirementTagId: string,
    @Body() dto: UpdateRequirementTagDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const result = await this.requirementTagService.update(
      organizationId,
      requirementTagId,
      dto,
      userId,
    );
    return SuccessHelper.createSuccessResponse(result, 'Requirement tag updated successfully');
  }

  @Delete(':requirementTagId')
  @HttpCode(HttpStatus.OK)
  async remove(
    @Param('organizationId') organizationId: string,
    @Param('requirementTagId') requirementTagId: string,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    await this.requirementTagService.remove(organizationId, requirementTagId, userId);
    return SuccessHelper.createSuccessResponse(null, 'Requirement tag deleted');
  }
}
