import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { PatientChatConversation } from '../entities/patient-chat-conversation.entity';
import { PatientChatMessage } from '../entities/patient-chat-message.entity';
import { CreateConversationDto } from '../dto/create-conversation.dto';
import { CreateMessageDto } from '../dto/create-message.dto';
import { QueryConversationsDto } from '../dto/query-conversations.dto';
import type { RecipientType } from '../entities/patient-chat-conversation.entity';

export interface ConversationListItem {
  id: string;
  organizationId: string | null;
  patientId: string | null;
  recipientType: RecipientType;
  recipientEntityId: string | null;
  recipientDisplayName: string;
  recipientRole: string | null;
  subject: string;
  lastMessagePreview: string | null;
  lastMessageAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface ConversationDetailDto extends ConversationListItem {
  messages: MessageItemDto[];
}

export interface MessageItemDto {
  id: string;
  conversationId: string;
  senderUserId: string;
  senderDisplayName: string;
  body: string;
  createdAt: string;
}

export interface RecipientItemDto {
  id: string;
  sender: string;
  role: string;
  initials: string;
  recipientType: RecipientType;
  recipientEntityId: string | null;
}

@Injectable()
export class PatientChatService {
  constructor(
    @InjectRepository(PatientChatConversation)
    private conversationRepository: Repository<PatientChatConversation>,
    @InjectRepository(PatientChatMessage)
    private messageRepository: Repository<PatientChatMessage>,
  ) {}

  private getInitials(displayName: string): string {
    const parts = displayName.trim().split(/\s+/).filter(Boolean);
    if (parts.length === 0) return '?';
    if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
    return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
  }

  async listConversations(
    userId: string,
    query: QueryConversationsDto,
  ): Promise<{ items: ConversationListItem[]; total: number }> {
    const qb = this.conversationRepository
      .createQueryBuilder('c')
      .leftJoinAndSelect('c.messages', 'm')
      .orderBy('c.updated_at', 'DESC');

    if (query.organizationId) {
      // Show conversations where this org is the context (organization_id) OR the recipient
      // (e.g. patient messaged this org; recipient_entity_id is the org id).
      qb.andWhere(
        '(c.organization_id = :organizationId OR (c.recipient_type = :orgType AND c.recipient_entity_id = :organizationId))',
        {
          organizationId: query.organizationId,
          orgType: 'organization',
        },
      );
    }
    if (query.patientId) {
      // Include conversations where patient_id is set OR the patient has sent any message
      // (covers conversations created from org side without patient_id)
      qb.andWhere(
        `(c.patient_id = :patientId OR EXISTS (
          SELECT 1 FROM patient_chat_messages m
          WHERE m.conversation_id = c.id AND m.sender_user_id = :patientId
        ))`,
        { patientId: query.patientId },
      );
    }

    const total = await qb.getCount();

    qb.take(query.limit ?? 50).skip(query.offset ?? 0);

    const conversations = await qb.getMany();

    const items: ConversationListItem[] = conversations.map((c) => {
      const sortedMessages = (c.messages ?? []).sort(
        (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
      );
      const last = sortedMessages[0];
      return {
        id: c.id,
        organizationId: c.organization_id,
        patientId: c.patient_id,
        recipientType: c.recipient_type,
        recipientEntityId: c.recipient_entity_id,
        recipientDisplayName: c.recipient_display_name,
        recipientRole: c.recipient_role,
        subject: c.subject ?? '(No subject)',
        lastMessagePreview: last
          ? (last.body ?? '').slice(0, 100) + (last.body.length > 100 ? '...' : '')
          : null,
        lastMessageAt: last
          ? (last.created_at instanceof Date
              ? last.created_at
              : new Date(last.created_at)
            ).toISOString()
          : null,
        createdAt: c.created_at instanceof Date ? c.created_at.toISOString() : String(c.created_at),
        updatedAt: c.updated_at instanceof Date ? c.updated_at.toISOString() : String(c.updated_at),
      };
    });

    return { items, total };
  }

  async createConversation(
    userId: string,
    dto: CreateConversationDto,
  ): Promise<ConversationDetailDto> {
    // When a patient messages an organization, set organization_id from recipientEntityId
    // so the conversation appears in that org's Messages list.
    const organizationId =
      dto.organizationId ??
      (dto.recipientType === 'organization' && dto.recipientEntityId
        ? dto.recipientEntityId
        : null);
    const conv = this.conversationRepository.create({
      organization_id: organizationId,
      patient_id: dto.patientId ?? null,
      recipient_type: dto.recipientType,
      recipient_entity_id: dto.recipientEntityId ?? null,
      recipient_display_name: dto.recipientDisplayName,
      recipient_role: dto.recipientRole ?? null,
      subject: dto.subject ?? '(No subject)',
    });
    const saved = await this.conversationRepository.save(conv);
    return this.getConversation(saved.id, userId);
  }

  async getConversation(conversationId: string, _userId: string): Promise<ConversationDetailDto> {
    const conv = await this.conversationRepository.findOne({
      where: { id: conversationId },
      relations: ['messages', 'messages.senderUser'],
      order: { messages: { created_at: 'ASC' } },
    });
    if (!conv) {
      throw new NotFoundException('Conversation not found');
    }
    const messages: MessageItemDto[] = (conv.messages ?? []).map((m) => ({
      id: m.id,
      conversationId: m.conversation_id,
      senderUserId: m.sender_user_id,
      senderDisplayName:
        (m.senderUser
          ? `${(m.senderUser as { firstName?: string; lastName?: string; email?: string }).firstName ?? ''} ${(m.senderUser as { firstName?: string; lastName?: string; email?: string }).lastName ?? ''}`.trim() ||
            (m.senderUser as { firstName?: string; lastName?: string; email?: string }).email
          : 'Unknown') ?? 'Unknown',
      body: m.body,
      createdAt: m.created_at instanceof Date ? m.created_at.toISOString() : String(m.created_at),
    }));

    const lastMsg = [...messages].sort(
      (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
    )[0];

    return {
      id: conv.id,
      organizationId: conv.organization_id,
      patientId: conv.patient_id,
      recipientType: conv.recipient_type,
      recipientEntityId: conv.recipient_entity_id,
      recipientDisplayName: conv.recipient_display_name,
      recipientRole: conv.recipient_role,
      subject: conv.subject ?? '(No subject)',
      lastMessagePreview: lastMsg
        ? lastMsg.body.slice(0, 100) + (lastMsg.body.length > 100 ? '...' : '')
        : null,
      lastMessageAt: lastMsg ? lastMsg.createdAt : null,
      createdAt:
        conv.created_at instanceof Date ? conv.created_at.toISOString() : String(conv.created_at),
      updatedAt:
        conv.updated_at instanceof Date ? conv.updated_at.toISOString() : String(conv.updated_at),
      messages,
    };
  }

  async listMessages(conversationId: string, _userId: string): Promise<MessageItemDto[]> {
    const conv = await this.conversationRepository.findOne({
      where: { id: conversationId },
      relations: ['messages', 'messages.senderUser'],
    });
    if (!conv) {
      throw new NotFoundException('Conversation not found');
    }
    const sorted = (conv.messages ?? []).sort(
      (a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime(),
    );
    return sorted.map((m) => ({
      id: m.id,
      conversationId: m.conversation_id,
      senderUserId: m.sender_user_id,
      senderDisplayName:
        (m.senderUser
          ? `${(m.senderUser as { firstName?: string; lastName?: string; email?: string }).firstName ?? ''} ${(m.senderUser as { firstName?: string; lastName?: string; email?: string }).lastName ?? ''}`.trim() ||
            (m.senderUser as { firstName?: string; lastName?: string; email?: string }).email
          : 'Unknown') ?? 'Unknown',
      body: m.body,
      createdAt: m.created_at instanceof Date ? m.created_at.toISOString() : String(m.created_at),
    }));
  }

  async sendMessage(
    conversationId: string,
    userId: string,
    dto: CreateMessageDto,
  ): Promise<MessageItemDto> {
    const conv = await this.conversationRepository.findOne({
      where: { id: conversationId },
    });
    if (!conv) {
      throw new NotFoundException('Conversation not found');
    }
    const msg = this.messageRepository.create({
      conversation_id: conversationId,
      sender_user_id: userId,
      body: dto.body,
    });
    const saved = await this.messageRepository.save(msg);

    const updatePayload: { updated_at: Date; patient_id?: string } = {
      updated_at: new Date(),
    };
    if (conv.patient_id == null) {
      updatePayload.patient_id = userId;
    }
    await this.conversationRepository.update({ id: conversationId }, updatePayload);

    let senderDisplayName = 'You';
    try {
      const withSender = await this.messageRepository.findOne({
        where: { id: saved.id },
        relations: ['senderUser'],
      });
      const u = withSender?.senderUser as
        | { firstName?: string; lastName?: string; email?: string }
        | undefined;
      if (u) {
        const name = `${u.firstName ?? ''} ${u.lastName ?? ''}`.trim();
        senderDisplayName = name || u.email || senderDisplayName;
      }
    } catch {
      // use "You" if loading sender fails
    }

    return {
      id: saved.id,
      conversationId: saved.conversation_id,
      senderUserId: saved.sender_user_id,
      senderDisplayName,
      body: saved.body,
      createdAt:
        saved.created_at instanceof Date
          ? saved.created_at.toISOString()
          : String(saved.created_at),
    };
  }

  /**
   * Returns list of recipients for the "New message" modal.
   * Can be extended to fetch from DB (e.g. org members, linked doctors) by category.
   */
  getRecipients(category?: RecipientType): Promise<RecipientItemDto[]> {
    // Static list for now; replace with DB/API when ready
    const all: RecipientItemDto[] = [
      {
        id: 'org-1',
        sender: 'Sunrise Home Health',
        role: 'Organization',
        initials: 'SH',
        recipientType: 'organization',
        recipientEntityId: null,
      },
      {
        id: 'org-2',
        sender: 'CareFirst Partners',
        role: 'Organization',
        initials: 'CP',
        recipientType: 'organization',
        recipientEntityId: null,
      },
      {
        id: 'lab-1',
        sender: 'Metro Lab Services',
        role: 'Lab',
        initials: 'ML',
        recipientType: 'lab',
        recipientEntityId: null,
      },
      {
        id: 'lab-2',
        sender: 'Quest Diagnostics',
        role: 'Lab',
        initials: 'QD',
        recipientType: 'lab',
        recipientEntityId: null,
      },
      {
        id: 'doc-1',
        sender: 'Dr. Jennifer Lee',
        role: 'Primary Care Physician',
        initials: 'DJL',
        recipientType: 'doctor',
        recipientEntityId: null,
      },
      {
        id: 'doc-2',
        sender: 'Dr. Michael Chen',
        role: 'Cardiologist',
        initials: 'DMC',
        recipientType: 'doctor',
        recipientEntityId: null,
      },
      {
        id: 'clin-1',
        sender: 'Sarah Johnson',
        role: 'Primary Nurse',
        initials: 'SJ',
        recipientType: 'clinical',
        recipientEntityId: null,
      },
      {
        id: 'clin-2',
        sender: 'Care Coordinator',
        role: 'Care Coordination',
        initials: 'CC',
        recipientType: 'clinical',
        recipientEntityId: null,
      },
      {
        id: 'ther-1',
        sender: 'Amanda Green',
        role: 'Physical Therapist',
        initials: 'AG',
        recipientType: 'therapist',
        recipientEntityId: null,
      },
      {
        id: 'ther-2',
        sender: 'James Wilson',
        role: 'Occupational Therapist',
        initials: 'JW',
        recipientType: 'therapist',
        recipientEntityId: null,
      },
    ];
    if (category) {
      return Promise.resolve(all.filter((r) => r.recipientType === category));
    }
    return Promise.resolve(all);
  }
}
