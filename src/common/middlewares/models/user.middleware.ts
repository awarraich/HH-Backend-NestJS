import { Injectable, NestMiddleware } from '@nestjs/common';
import { FastifyRequest, FastifyReply } from 'fastify';

@Injectable()
export class UserMiddleware implements NestMiddleware {
  use(req: FastifyRequest['raw'], res: FastifyReply['raw'], next: () => void) {
    // HIPAA Compliance: Log user access for audit trail
    // Implement user context extraction and logging
    console.warn('User middleware executed');
    next();
  }
}
