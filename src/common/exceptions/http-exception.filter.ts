import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { FastifyReply, FastifyRequest } from 'fastify';

@Catch()
export class HttpExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(HttpExceptionFilter.name);

  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<FastifyReply>();
    const request = ctx.getRequest<FastifyRequest>();

    let status = HttpStatus.INTERNAL_SERVER_ERROR;
    let message: string | string[] = 'Internal server error';

    if (exception instanceof HttpException) {
      status = exception.getStatus();
      const exceptionResponse = exception.getResponse();
      const res = exceptionResponse as Record<string, unknown> | string;
      message =
        typeof res === 'string'
          ? res
          : ((res.message as string | string[] | undefined) ?? exception.message);
    } else {
      const err = exception as Error;
      message = err?.message || String(exception);
      this.logger.error(`Unhandled exception: ${message}`, err?.stack);
    }

    const body: Record<string, unknown> = {
      statusCode: status,
      timestamp: new Date().toISOString(),
      path: request.url,
      message,
    };
    if (
      status === HttpStatus.INTERNAL_SERVER_ERROR &&
      process.env.NODE_ENV !== 'production' &&
      exception instanceof Error
    ) {
      body.error = exception.message;
    }
    response.status(status).send(body);
  }
}
