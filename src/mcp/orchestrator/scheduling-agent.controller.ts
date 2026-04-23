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
  ArrayMaxSize,
  IsArray,
  IsIn,
  IsNotEmpty,
  IsObject,
  IsOptional,
  IsString,
  IsUUID,
  MaxLength,
  ValidateNested,
} from 'class-validator';
import { Type } from 'class-transformer';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { OrganizationRoleGuard } from '../../common/guards/organization-role.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { SuccessHelper } from '../../common/helpers/responses/success.helper';
import { SchedulingAgentService } from './scheduling-agent.service';
import type {
  SchedulingAgentContext,
  SchedulingAgentHistoryMessage,
  SchedulingAgentToolCall,
} from './scheduling-agent.service';

class SchedulingAgentHistoryMessageDto implements SchedulingAgentHistoryMessage {
  @IsString()
  @IsIn(['user', 'assistant'])
  role: 'user' | 'assistant';

  @IsString()
  @IsNotEmpty()
  @MaxLength(8000)
  content: string;
}

class SchedulingAgentToolCallDto implements SchedulingAgentToolCall {
  @IsString()
  @IsNotEmpty()
  @MaxLength(100)
  name: string;

  @IsOptional()
  arguments: unknown;

  @IsOptional()
  result: unknown;
}

class SchedulingAgentDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(2000)
  query: string;

  @IsUUID()
  organizationId: string;

  /**
   * Client-supplied IANA timezone (e.g. "America/Los_Angeles"). The frontend
   * should derive this from `Intl.DateTimeFormat().resolvedOptions().timeZone`
   * and send it on every request so shift times render in the user's local
   * time. Falls back to America/Los_Angeles (US Pacific) if missing or invalid.
   */
  @IsOptional()
  @IsString()
  @MaxLength(100)
  timezone?: string;

  /**
   * Prior conversation turns (oldest first), excluding the current `query`.
   * The frontend should keep this in component state / localStorage and send
   * the last ~20 turns on every request to bound payload size.
   */
  @IsOptional()
  @IsArray()
  @ArrayMaxSize(40)
  @ValidateNested({ each: true })
  @Type(() => SchedulingAgentHistoryMessageDto)
  history?: SchedulingAgentHistoryMessageDto[];

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

  /**
   * Tool-call trace from the previous response (pass through the
   * `toolCalls` array from the last response body, capped client-side to
   * the last ~12 calls). Lets the server replay prior UUIDs so a "yes"
   * confirmation turn doesn't lose context.
   */
  @IsOptional()
  @IsArray()
  @ArrayMaxSize(24)
  @ValidateNested({ each: true })
  @Type(() => SchedulingAgentToolCallDto)
  priorToolCalls?: SchedulingAgentToolCallDto[];
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
      timezone: dto.timezone,
      history: dto.history,
      priorToolCalls: dto.priorToolCalls,
    });

    return SuccessHelper.createSuccessResponse(result);
  }
}
