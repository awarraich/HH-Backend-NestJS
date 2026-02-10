import {
  WebSocketGateway,
  WebSocketServer,
  SubscribeMessage,
  OnGatewayConnection,
  OnGatewayDisconnect,
} from '@nestjs/websockets';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { Server } from 'socket.io';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../../../authentication/entities/user.entity';
import { Referral } from '../entities/referral.entity';
import { OrganizationRoleService } from '../services/organization-role.service';
import type { JwtPayload } from '../../../authentication/interfaces/jwt-payload.interface';

const ROOM_PREFIX = 'referral:';

@WebSocketGateway(0, { namespace: '/referrals', transports: ['websocket', 'polling'] })
export class ReferralMessagesGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer()
  server!: Server;

  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly organizationRoleService: OrganizationRoleService,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(Referral)
    private readonly referralRepository: Repository<Referral>,
  ) {}

  async handleConnection(client: any): Promise<void> {
    const token =
      client.handshake?.auth?.token ||
      client.handshake?.query?.token ||
      client.handshake?.headers?.authorization?.replace?.('Bearer ', '');
    if (!token) {
      client.disconnect();
      return;
    }
    try {
      const secret = this.configService.get<string>('JWT_SECRET') || 'your-secret-key';
      const payload = await this.jwtService.verifyAsync<JwtPayload>(token, { secret });
      if (payload.is2FAPending || !payload.sub) {
        client.disconnect();
        return;
      }
      const user = await this.userRepository.findOne({
        where: { id: payload.sub },
        select: ['id', 'is_active', 'password_changed_at'],
      });
      if (!user || !user.is_active) {
        client.disconnect();
        return;
      }
      if (payload.iat && user.password_changed_at) {
        const tokenIat = payload.iat * 1000;
        const pwdChanged = new Date(user.password_changed_at).getTime();
        if (pwdChanged > tokenIat) {
          client.disconnect();
          return;
        }
      }
      client.data.userId = payload.sub;
    } catch {
      client.disconnect();
    }
  }

  handleDisconnect(): void {}

  @SubscribeMessage('subscribe_referral')
  async handleSubscribeReferral(
    client: any,
    payload: { referralId: string; organizationId: string },
  ): Promise<{ success: boolean; error?: string }> {
    const userId = client.data?.userId;
    if (!userId) return { success: false, error: 'Unauthorized' };
    if (!payload?.referralId || !payload?.organizationId) {
      return { success: false, error: 'referralId and organizationId required' };
    }
    const { referralId, organizationId } = payload;
    const role = await this.organizationRoleService.getUserRoleInOrganization(
      userId,
      organizationId,
    );
    if (!role) {
      return { success: false, error: 'No access to this organization' };
    }
    const referral = await this.referralRepository.findOne({
      where: { id: referralId },
      relations: ['referralOrganizations'],
    });
    if (!referral) return { success: false, error: 'Referral not found' };
    const isSender = referral.sending_organization_id === organizationId;
    const isReceiver = referral.referralOrganizations?.some(
      (ro) => ro.organization_id === organizationId,
    );
    if (!isSender && !isReceiver) {
      return { success: false, error: 'No access to this referral' };
    }
    const room = `${ROOM_PREFIX}${referralId}`;
    await client.join(room);
    return { success: true };
  }

  emitNewMessage(
    referralId: string,
    receiverOrganizationId: string | null,
    senderOrganizationId: string,
    messagePayload: {
      id: string;
      message: string;
      is_system: boolean;
      sender_user_id: string | null;
      sender_organization_id: string | null;
      sender_name?: string | null;
      created_at: Date;
      receiver_organization_id?: string | null;
    },
  ): void {
    const room = `${ROOM_PREFIX}${referralId}`;
    this.server.to(room).emit('new_message', {
      ...messagePayload,
      receiver_organization_id: receiverOrganizationId ?? undefined,
    });
  }

  emitReadReceipt(referralId: string, organizationId: string, readAt: Date): void {
    const room = `${ROOM_PREFIX}${referralId}`;
    this.server.to(room).emit('read_receipt', { organizationId, readAt });
  }
}
