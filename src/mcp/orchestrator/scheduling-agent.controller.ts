import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Request,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import {
  IsNotEmpty,
  IsObject,
  IsOptional,
  IsString,
  IsUUID,
  MaxLength,
} from 'class-validator';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { OrganizationRoleGuard } from '../../common/guards/organization-role.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { SuccessHelper } from '../../common/helpers/responses/success.helper';
import { SchedulingAgentService } from './scheduling-agent.service';
import type { SchedulingAgentContext } from './scheduling-agent.service';

class SchedulingAgentDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(2000)
  query: string;

  @IsUUID()
  organizationId: string;

  /**
   * Optional UI context — whatever the user is currently looking at on the
   * page. The agent uses these as defaults when the user's query omits a
   * specific shift / department / station / date.
   *
   * All fields are free-form strings; the frontend should pass IDs and human
   * names whenever it knows them. Unknown keys are ignored.
   */
  @IsOptional()
  @IsObject()
  context?: SchedulingAgentContext;
}

type RequestWithUser = FastifyRequest & {
  user?: { userId?: string; sub?: string };
};

@Controller('v1/api/scheduling-agent')
@UseGuards(JwtAuthGuard, OrganizationRoleGuard)
@Roles('OWNER', 'HR', 'MANAGER')
export class SchedulingAgentController {
  constructor(private readonly agent: SchedulingAgentService) {}

  @Post()
  @HttpCode(HttpStatus.OK)
  async chat(@Body() dto: SchedulingAgentDto, @Request() req: RequestWithUser) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');

    const result = await this.agent.chat({
      userId,
      organizationId: dto.organizationId,
      query: dto.query,
      context: dto.context,
    });

    return SuccessHelper.createSuccessResponse(result);
  }
}
