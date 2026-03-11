import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Param,
  Body,
  UseGuards,
  Req,
  HttpCode,
  HttpStatus,
  ParseUUIDPipe,
} from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import { JwtAuthGuard } from '../../../../common/guards/jwt-auth.guard';
import { OrganizationRoleGuard } from '../../../../common/guards/organization-role.guard';
import { Roles } from '../../../../common/decorators/roles.decorator';
import { SuccessHelper } from '../../../../common/helpers/responses/success.helper';
import { InserviceQuizQuestionService } from '../services/inservice-quiz-question.service';
import { CreateInserviceQuizQuestionDto } from '../dto/create-inservice-quiz-question.dto';
import { UpdateInserviceQuizQuestionDto } from '../dto/update-inservice-quiz-question.dto';

/**
 * Quiz questions under organization-scoped path.
 * Same behavior as InserviceQuizQuestionsController; use inserviceId only for the service.
 */
@Controller('v1/api/organizations/:organizationId/inservice-trainings/:inserviceId/quiz-questions')
@UseGuards(JwtAuthGuard, OrganizationRoleGuard)
@Roles('OWNER', 'HR', 'MANAGER')
@Controller(
  'v1/api/organizations/:organizationId/inservice-trainings/:inserviceId/quiz-questions',
)
// @UseGuards(JwtAuthGuard)
// @Roles('OWNER', 'HR', 'MANAGER')
export class InserviceQuizQuestionsOrgController {
  constructor(private readonly inserviceQuizQuestionService: InserviceQuizQuestionService) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async findAll(
    @Param('inserviceId', ParseUUIDPipe) inserviceId: string,
    @Req() req: FastifyRequest & { user?: { userId?: string; sub?: string } },
  ) {
    const userId = req.user?.userId ?? req.user?.sub ?? '';
    const result = await this.inserviceQuizQuestionService.findAll(inserviceId, userId);
    return SuccessHelper.createSuccessResponse(result);
  }

  @Get(':questionId')
  @HttpCode(HttpStatus.OK)
  async findOne(
    @Param('inserviceId', ParseUUIDPipe) inserviceId: string,
    @Param('questionId', ParseUUIDPipe) questionId: string,
    @Req() req: FastifyRequest & { user?: { userId?: string; sub?: string } },
  ) {
    const userId = req.user?.userId ?? req.user?.sub ?? '';
    const result = await this.inserviceQuizQuestionService.findOne(inserviceId, questionId, userId);
    return SuccessHelper.createSuccessResponse(result);
  }

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async create(
    @Param('inserviceId', ParseUUIDPipe) inserviceId: string,
    @Body() dto: CreateInserviceQuizQuestionDto,
    @Req() req: FastifyRequest & { user?: { userId?: string; sub?: string } },
  ) {
    const userId = req.user?.userId ?? req.user?.sub ?? '';
    const result = await this.inserviceQuizQuestionService.create(inserviceId, dto, userId);
    return SuccessHelper.createSuccessResponse(result, 'Quiz question created successfully');
  }

  @Patch(':questionId')
  @HttpCode(HttpStatus.OK)
  async update(
    @Param('inserviceId', ParseUUIDPipe) inserviceId: string,
    @Param('questionId', ParseUUIDPipe) questionId: string,
    @Body() dto: UpdateInserviceQuizQuestionDto,
    @Req() req: FastifyRequest & { user?: { userId?: string; sub?: string } },
  ) {
    const userId = req.user?.userId ?? req.user?.sub ?? '';
    const result = await this.inserviceQuizQuestionService.update(
      inserviceId,
      questionId,
      dto,
      userId,
    );
    return SuccessHelper.createSuccessResponse(result, 'Quiz question updated successfully');
  }

  @Delete(':questionId')
  @HttpCode(HttpStatus.OK)
  async remove(
    @Param('inserviceId', ParseUUIDPipe) inserviceId: string,
    @Param('questionId', ParseUUIDPipe) questionId: string,
    @Req() req: FastifyRequest & { user?: { userId?: string; sub?: string } },
  ) {
    const userId = req.user?.userId ?? req.user?.sub ?? '';
    await this.inserviceQuizQuestionService.remove(inserviceId, questionId, userId);
    return SuccessHelper.createSuccessResponse(null, 'Quiz question deleted successfully');
  }
}
