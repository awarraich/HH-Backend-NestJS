import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  Query,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { LoggedInUser } from '../../common/decorators/requests/logged-in-user.decorator';
import type { UserWithRolesInterface } from '../../common/interfaces/user-with-roles.interface';
import { SuccessHelper } from '../../common/helpers/responses/success.helper';
import { PatientChatService } from './patient-chat.service';
import { CreateConversationDto } from './dto/create-conversation.dto';
import { CreateMessageDto } from './dto/create-message.dto';
import { QueryConversationsDto } from './dto/query-conversations.dto';
import { QueryRecipientsDto } from './dto/query-recipients.dto';

@Controller('v1/api/patient-chat')
@UseGuards(JwtAuthGuard)
export class PatientChatController {
  constructor(private readonly patientChatService: PatientChatService) {}

  @Get('conversations')
  @HttpCode(HttpStatus.OK)
  async listConversations(
    @LoggedInUser() user: UserWithRolesInterface,
    @Query() query: QueryConversationsDto,
  ) {
    const result = await this.patientChatService.listConversations(
      user.userId,
      query,
    );
    return SuccessHelper.createSuccessResponse(result);
  }

  @Post('conversations')
  @HttpCode(HttpStatus.CREATED)
  async createConversation(
    @LoggedInUser() user: UserWithRolesInterface,
    @Body() dto: CreateConversationDto,
  ) {
    const data = await this.patientChatService.createConversation(
      user.userId,
      dto,
    );
    return SuccessHelper.createSuccessResponse(data, 'Conversation created');
  }

  @Get('conversations/:conversationId')
  @HttpCode(HttpStatus.OK)
  async getConversation(
    @LoggedInUser() user: UserWithRolesInterface,
    @Param('conversationId') conversationId: string,
  ) {
    const data = await this.patientChatService.getConversation(
      conversationId,
      user.userId,
    );
    return SuccessHelper.createSuccessResponse(data);
  }

  @Get('conversations/:conversationId/messages')
  @HttpCode(HttpStatus.OK)
  async listMessages(
    @LoggedInUser() user: UserWithRolesInterface,
    @Param('conversationId') conversationId: string,
  ) {
    const data = await this.patientChatService.listMessages(
      conversationId,
      user.userId,
    );
    return SuccessHelper.createSuccessResponse(data);
  }

  @Post('conversations/:conversationId/messages')
  @HttpCode(HttpStatus.CREATED)
  async sendMessage(
    @LoggedInUser() user: UserWithRolesInterface,
    @Param('conversationId') conversationId: string,
    @Body() dto: CreateMessageDto,
  ) {
    const data = await this.patientChatService.sendMessage(
      conversationId,
      user.userId,
      dto,
    );
    return SuccessHelper.createSuccessResponse(data, 'Message sent');
  }

  @Get('recipients')
  @HttpCode(HttpStatus.OK)
  async getRecipients(@Query() query: QueryRecipientsDto) {
    const data = await this.patientChatService.getRecipients(query.category);
    return SuccessHelper.createSuccessResponse(data);
  }
}
