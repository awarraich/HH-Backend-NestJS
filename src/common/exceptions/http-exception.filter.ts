import { ExceptionFilter, Catch, ArgumentsHost, HttpException, HttpStatus } from '@nestjs/common';
import { FastifyReply, FastifyRequest } from 'fastify';

@Catch(HttpException)
export class HttpExceptionFilter implements ExceptionFilter {
  catch(exception: HttpException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<FastifyReply>();
    const request = ctx.getRequest<FastifyRequest>();
    const status = exception.getStatus();
    const exceptionResponse = exception.getResponse();

    // #region agent log
    fetch('http://127.0.0.1:7245/ingest/7783f4d7-3b3d-4394-bfb4-219a26c78f26',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'http-exception.filter.ts:11',message:'exception filter caught',data:{status,exceptionMessage:exception.message,path:request.url,responseSent:response.sent,responseStatusCode:response.statusCode,exceptionResponseType:typeof exceptionResponse},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'H2,H5'})}).catch(()=>{});
    // #endregion

    // HIPAA Compliance: Log all exceptions for audit trail
    console.error('HTTP Exception:', {
      status,
      message: exception.message,
      path: request.url,
      method: request.method,
      timestamp: new Date().toISOString(),
      // In production, log to secure audit log system
    });

    // #region agent log
    fetch('http://127.0.0.1:7245/ingest/7783f4d7-3b3d-4394-bfb4-219a26c78f26',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'http-exception.filter.ts:28',message:'before response.send in filter',data:{responseSent:response.sent,responseStatusCode:response.statusCode},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'H4,H5'})}).catch(()=>{});
    // #endregion
    try {
      response.status(status).send({
        statusCode: status,
        timestamp: new Date().toISOString(),
        path: request.url,
        message:
          typeof exceptionResponse === 'string'
            ? exceptionResponse
            : (exceptionResponse as any).message || exception.message,
        error: typeof exceptionResponse === 'object' ? (exceptionResponse as any).error : undefined,
      });
      // #region agent log
      fetch('http://127.0.0.1:7245/ingest/7783f4d7-3b3d-4394-bfb4-219a26c78f26',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'http-exception.filter.ts:40',message:'after response.send in filter',data:{responseSent:response.sent},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'H4,H5'})}).catch(()=>{});
      // #endregion
    } catch (sendError: any) {
      // #region agent log
      fetch('http://127.0.0.1:7245/ingest/7783f4d7-3b3d-4394-bfb4-219a26c78f26',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'http-exception.filter.ts:43',message:'error in filter send',data:{sendErrorMessage:sendError?.message,sendErrorStack:sendError?.stack,sendErrorName:sendError?.name,responseSent:response.sent},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'H4,H5'})}).catch(()=>{});
      // #endregion
      throw sendError;
    }
  }
}
