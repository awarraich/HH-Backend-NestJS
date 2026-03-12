import { Controller, Post, Body, Req, UseGuards, HttpCode, HttpStatus } from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import { JwtAuthGuard } from '../../../common/guards/jwt-auth.guard';
import { LoggedInUser } from '../../../common/decorators/requests/logged-in-user.decorator';
import type { UserWithRolesInterface } from '../../../common/interfaces/user-with-roles.interface';
import { SuccessHelper } from '../../../common/helpers/responses/success.helper';
import { DigitalNurseChatService } from './digital-nurse-chat.service';
import { DigitalNurseChatRequestDto } from './dto/chat-request.dto';

@Controller('v1/api/patients/me/digital-nurse')
@UseGuards(JwtAuthGuard)
export class DigitalNurseChatController {
  constructor(private readonly digitalNurseChatService: DigitalNurseChatService) {}

  private getIpAddress(request: FastifyRequest): string {
    const forwarded = request.headers['x-forwarded-for'];
    if (forwarded) {
      return Array.isArray(forwarded) ? forwarded[0] : forwarded.split(',')[0];
    }
    return request.ip ?? (request.socket as { remoteAddress?: string })?.remoteAddress ?? 'unknown';
  }

  private getUserAgent(request: FastifyRequest): string {
    return (request.headers['user-agent'] as string) ?? 'unknown';
  }

  @Post('chat')
  @HttpCode(HttpStatus.OK)
  async chat(
    @LoggedInUser() user: UserWithRolesInterface,
    @Body() dto: DigitalNurseChatRequestDto,
    @Req() request: FastifyRequest,
  ): Promise<unknown> {
    const auditContext = {
      userId: user.userId,
      ipAddress: this.getIpAddress(request),
      userAgent: this.getUserAgent(request),
    };
    const history = dto.history as { role: 'user' | 'assistant'; content: string }[] | undefined;
    const result = await this.digitalNurseChatService.chat(
      user.userId,
      dto.message,
      auditContext,
      history,
    );
    return SuccessHelper.createSuccessResponse(result);
  }
}
