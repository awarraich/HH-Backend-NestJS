import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  BadRequestException,
  Optional,
  Inject,
  forwardRef,
  Logger,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Referral } from '../entities/referral.entity';
import { ReferralMessage } from '../entities/referral-message.entity';
import { ReferralLastRead } from '../entities/referral-last-read.entity';
import { CreateReferralMessageDto } from '../dto/create-referral-message.dto';
import { QueryReferralMessagesDto } from '../dto/query-referral-messages.dto';
import { AuditLogService } from '../../../common/services/audit/audit-log.service';
import { ReferralMessagesGateway } from '../gateways/referral-messages.gateway';

@Injectable()
export class ReferralMessagesService {
  private readonly logger = new Logger(ReferralMessagesService.name);

  constructor(
    @InjectRepository(Referral)
    private referralRepository: Repository<Referral>,
    @InjectRepository(ReferralMessage)
    private referralMessageRepository: Repository<ReferralMessage>,
    @InjectRepository(ReferralLastRead)
    private referralLastReadRepository: Repository<ReferralLastRead>,
    private auditLogService: AuditLogService,
    @Optional()
    @Inject(forwardRef(() => ReferralMessagesGateway))
    private referralMessagesGateway?: ReferralMessagesGateway,
  ) {}

  private async ensureAccess(referralId: string, organizationId: string): Promise<Referral> {
    const referral = await this.referralRepository.findOne({
      where: { id: referralId },
      relations: ['referralOrganizations'],
    });
    if (!referral) throw new NotFoundException('Referral not found');
    const isSender = referral.sending_organization_id === organizationId;
    const isReceiver = referral.referralOrganizations?.some(
      (ro) => ro.organization_id === organizationId,
    );
    if (!isSender && !isReceiver) {
      throw new ForbiddenException('You do not have access to this referral');
    }
    return referral;
  }

  async getThreads(
    organizationId: string,
    referralId: string,
    userId?: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<any[]> {
    const referral = await this.ensureAccess(referralId, organizationId);
    const sendingOrgId = referral.sending_organization_id;
    const receiverOrgIds = referral.referralOrganizations?.map((ro) => ro.organization_id) ?? [];
    const otherOrgIds =
      organizationId === sendingOrgId ? receiverOrgIds : [sendingOrgId];

    const threads: any[] = [];
    for (const otherId of otherOrgIds) {
      const lastMsg = await this.referralMessageRepository
        .createQueryBuilder('m')
        .where('m.referral_id = :referralId', { referralId })
        .andWhere(
          '(m.receiver_organization_id = :otherId OR m.sender_organization_id = :otherId)',
          { otherId },
        )
        .orderBy('m.created_at', 'DESC')
        .getOne();

      const lastRead = await this.referralLastReadRepository.findOne({
        where: { referral_id: referralId, organization_id: organizationId },
      });
      let unreadCount = 0;
      const unreadQb = this.referralMessageRepository
        .createQueryBuilder('m')
        .where('m.referral_id = :referralId', { referralId })
        .andWhere(
          '(m.receiver_organization_id = :otherId OR m.sender_organization_id = :otherId)',
          { otherId },
        )
        .andWhere('m.sender_organization_id != :organizationId', { organizationId })
        .andWhere('m.is_system = false');
      if (lastRead) {
        unreadQb.andWhere('m.created_at > :lastReadAt', {
          lastReadAt: lastRead.last_read_at,
        });
      }
      unreadCount = await unreadQb.getCount();

      threads.push({
        organization_id: otherId,
        last_message: lastMsg
          ? { message: lastMsg.message, created_at: lastMsg.created_at }
          : null,
        unread_count: unreadCount,
      });
    }
    return threads;
  }

  async getMessages(
    organizationId: string,
    referralId: string,
    queryDto: QueryReferralMessagesDto,
    userId?: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<{ data: any[]; total: number; page: number; limit: number }> {
    await this.ensureAccess(referralId, organizationId);
    if (!queryDto.receiver_organization_id) {
      return {
        data: [],
        total: 0,
        page: queryDto.page ?? 1,
        limit: queryDto.limit ?? 20,
      };
    }
    const otherId = queryDto.receiver_organization_id;
    const page = queryDto.page ?? 1;
    const limit = queryDto.limit ?? 20;

    const qb = this.referralMessageRepository
      .createQueryBuilder('m')
      .leftJoinAndSelect('m.senderUser', 'senderUser')
      .leftJoinAndSelect('m.senderOrganization', 'senderOrg')
      .where('m.referral_id = :referralId', { referralId })
      .andWhere(
        '(m.receiver_organization_id = :otherId OR m.sender_organization_id = :otherId)',
        { otherId },
      )
      .orderBy('m.created_at', 'ASC');

    const [data, total] = await qb
      .skip((page - 1) * limit)
      .take(limit)
      .getManyAndCount();

    const items = data.map((m) => ({
      id: m.id,
      message: m.message,
      is_system: m.is_system,
      sender_user_id: m.sender_user_id,
      sender_organization_id: m.sender_organization_id,
      sender_name: m.senderUser
        ? `${(m.senderUser as any).firstName} ${(m.senderUser as any).lastName}`
        : m.senderOrganization?.organization_name ?? null,
      created_at: m.created_at,
    }));

    return { data: items, total, page, limit };
  }

  async send(
    organizationId: string,
    userId: string,
    referralId: string,
    dto: CreateReferralMessageDto,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<any> {
    const referral = await this.ensureAccess(referralId, organizationId);
    const receiverOrgId = dto.receiver_organization_id ?? null;

    if (!receiverOrgId) {
      const msg = this.referralMessageRepository.create({
        referral_id: referralId,
        message: dto.message,
        is_system: true,
        sender_user_id: userId,
        sender_organization_id: organizationId,
      });
      const saved = await this.referralMessageRepository.save(msg);
      this.emitNewMessageSafe(referralId, null, organizationId, saved);
      return { id: saved.id, message: saved.message, created_at: saved.created_at };
    }

    const receiverIds = referral.referralOrganizations?.map((ro) => ro.organization_id) ?? [];
    const validOther =
      receiverIds.includes(receiverOrgId) ||
      referral.sending_organization_id === receiverOrgId;
    if (!validOther) {
      throw new BadRequestException('Invalid receiver_organization_id for this referral');
    }

    const msg = this.referralMessageRepository.create({
      referral_id: referralId,
      receiver_organization_id: receiverOrgId,
      sender_user_id: userId,
      sender_organization_id: organizationId,
      message: dto.message,
      is_system: false,
    });
    const saved = await this.referralMessageRepository.save(msg);
    this.emitNewMessageSafe(referralId, receiverOrgId, organizationId, saved);
    return {
      id: saved.id,
      message: saved.message,
      receiver_organization_id: saved.receiver_organization_id,
      created_at: saved.created_at,
    };
  }

  private async emitNewMessageSafe(
    referralId: string,
    receiverOrganizationId: string | null,
    senderOrganizationId: string,
    saved: ReferralMessage,
  ): Promise<void> {
    if (!this.referralMessagesGateway) return;
    try {
      const withRelations = await this.referralMessageRepository.findOne({
        where: { id: saved.id },
        relations: ['senderUser', 'senderOrganization'],
      });
      const senderName = withRelations?.senderUser
        ? `${(withRelations.senderUser as any).firstName} ${(withRelations.senderUser as any).lastName}`
        : withRelations?.senderOrganization?.organization_name ?? null;
      this.referralMessagesGateway.emitNewMessage(
        referralId,
        receiverOrganizationId,
        senderOrganizationId,
        {
          id: saved.id,
          message: saved.message,
          is_system: saved.is_system,
          sender_user_id: saved.sender_user_id,
          sender_organization_id: saved.sender_organization_id,
          sender_name: senderName,
          created_at: saved.created_at,
          receiver_organization_id: saved.receiver_organization_id ?? undefined,
        },
      );
    } catch (err) {
      this.logger.warn('Failed to emit new_message over WebSocket', err);
    }
  }

  async markRead(
    organizationId: string,
    referralId: string,
    userId?: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<void> {
    await this.ensureAccess(referralId, organizationId);
    let lastRead = await this.referralLastReadRepository.findOne({
      where: { referral_id: referralId, organization_id: organizationId },
    });
    const now = new Date();
    if (lastRead) {
      lastRead.last_read_at = now;
      await this.referralLastReadRepository.save(lastRead);
    } else {
      lastRead = this.referralLastReadRepository.create({
        referral_id: referralId,
        organization_id: organizationId,
        last_read_at: now,
      });
      await this.referralLastReadRepository.save(lastRead);
    }
    if (this.referralMessagesGateway) {
      try {
        this.referralMessagesGateway.emitReadReceipt(referralId, organizationId, now);
      } catch (err) {
        this.logger.warn('Failed to emit read_receipt over WebSocket', err);
      }
    }
  }
}
