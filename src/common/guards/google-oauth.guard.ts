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
  getAuthenticateOptions(_context: ExecutionContext) {
    // `accessType: 'offline'` + `prompt: 'consent'` are required for Google to
    // return a refresh_token. Without them we only ever get a 1-hour access
    // token, which is not enough to call Calendar API later when HR schedules
    // an interview hours/days after signing in.
    // `includeGrantedScopes` keeps previously granted scopes so re-consent
    // doesn't shrink the user's permissions.
    return {
      accessType: 'offline',
      prompt: 'consent',
      includeGrantedScopes: 'true',
    };
  }

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
      expressResponse.end = (chunk?: unknown, _encoding?: string) => {
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
