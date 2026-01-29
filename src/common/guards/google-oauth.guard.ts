import { Injectable, ExecutionContext } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { FastifyReply, FastifyRequest } from 'fastify';

// Extend FastifyReply interface to include Express-compatible methods
interface ExpressCompatibleResponse extends FastifyReply {
  setHeader?: (name: string, value: string) => void;
  end?: (chunk?: any, encoding?: any) => void;
}

@Injectable()
export class GoogleOAuthGuard extends AuthGuard('google') {
  getRequest(context: ExecutionContext): FastifyRequest {
    return context.switchToHttp().getRequest<FastifyRequest>();
  }

  getResponse(context: ExecutionContext): ExpressCompatibleResponse {
    const response = context.switchToHttp().getResponse<FastifyReply>();
    const expressResponse = response as ExpressCompatibleResponse;
    
    // Add Express-compatible methods to Fastify response for Passport compatibility
    if (!expressResponse.setHeader) {
      expressResponse.setHeader = (name: string, value: string) => {
        response.header(name, value);
      };
    }
    
    if (!expressResponse.end) {
      expressResponse.end = (chunk?: any, encoding?: any) => {
        if (chunk) {
          response.send(chunk);
        } else {
          response.send();
        }
      };
    }

    return expressResponse;
  }

  handleRequest(err: any, user: any, info: any, context: ExecutionContext) {
    // Ensure response has Express-compatible methods
    this.getResponse(context);
    return super.handleRequest(err, user, info, context);
  }
}

