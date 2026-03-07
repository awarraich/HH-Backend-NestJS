import { NestFactory } from '@nestjs/core';
import { FastifyAdapter, NestFastifyApplication } from '@nestjs/platform-fastify';
import { ValidationPipe } from '@nestjs/common';
import * as http from 'node:http';
import { AppModule } from './app.module';
import { AuthenticationModule } from './authentication/auth.module';
import { AppConfigService } from './config/app/config.service';
import { HttpExceptionFilter } from './common/exceptions/http-exception.filter';
import { AuthService } from './authentication/services/auth.service';
import { GoogleOAuthGuard } from './common/guards/google-oauth.guard';
import { SocketIoAdapter } from './common/adapters/socket-io.adapter';
import { McpHttpHandlerService } from './mcp/mcp-http-handler.service';
import { JobManagementService } from './models/job-management/job-management.service';
import { BlogService } from './models/blog/blog.service';
import { SuccessHelper } from './common/helpers/responses/success.helper';

async function bootstrap() {
  const app = await NestFactory.create<NestFastifyApplication>(AppModule, new FastifyAdapter({logger: true}));

  const httpPort = parseInt(process.env.PORT || '3000', 10);
  // const wsPort = parseInt(process.env.WS_PORT || String(httpPort + 1), 10);
  let allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',').map((o) => o.trim()).filter(Boolean) ||
    (process.env.HOME_HEALTH_AI_URL ? [process.env.HOME_HEALTH_AI_URL] : []) ||
    (process.env.FRONTEND_URL ? [process.env.FRONTEND_URL] : []);
  // Production fallback: allow live frontend so CORS works when ALLOWED_ORIGINS/FRONTEND_URL not set
  if (allowedOrigins.length === 0 && process.env.NODE_ENV === 'production') {
    allowedOrigins = ['https://homehealth.ai', 'https://www.homehealth.ai'];
  }
  app.useWebSocketAdapter(
  new SocketIoAdapter(app, allowedOrigins.length > 0 ? allowedOrigins : false)
);

  const appConfigService = app.get(AppConfigService);
  const apiPrefix = appConfigService.apiPrefix;

  const fastifyInstance = app.getHttpAdapter().getInstance();

  // Health check at fixed path so production can verify this Nest app (with blogs) is the one serving api.homehealth.ai
  fastifyInstance.get('/v1/api/health', (_request: any, reply: any) => {
    reply.send({ ok: true, service: 'hh-backend', blogs: true, timestamp: new Date().toISOString() });
  });

  await fastifyInstance.register(require('@fastify/multipart'), {
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
    attachFieldsToBody: true, // so multipart create can read "data" field from body
  });

  await app.init();
  const moduleRef = app.select(AuthenticationModule);
  const authService = moduleRef.get(AuthService, { strict: false });
  const googleOAuthGuard = moduleRef.get(GoogleOAuthGuard, { strict: false });
  
  fastifyInstance.get('/accounts/google/login/callback/', async (request: any, reply: any) => {
    try {
      if (!reply.setHeader) {
        (reply as any).setHeader = (name: string, value: string) => {
          reply.header(name, value);
        };
      }
      if (!reply.end) {
        (reply as any).end = (chunk?: any) => {
          if (chunk) reply.send(chunk);
          else reply.send();
        };
      }
      
      // Create execution context for the guard
      const context = {
        switchToHttp: () => ({
          getRequest: () => request,
          getResponse: () => reply,
        }),
        getHandler: () => ({}),
        getClass: () => ({}),
      } as any;
      
      // Run the Passport guard to authenticate
      const canActivate = await googleOAuthGuard.canActivate(context);
      if (!canActivate) {
        reply.code(401).send({ message: 'OAuth authentication failed' });
        return;
      }
      
      // Get authenticated user from request (set by Passport)
      const googleProfile = (request as any).user;
      
      if (!googleProfile) {
        reply.code(401).send({ message: 'OAuth authentication incomplete' });
        return;
      }
      
      // Process OAuth login
      const result = await authService.googleLogin(googleProfile);

      const frontendUrl =
        process.env.HOME_HEALTH_AI_URL || process.env.FRONTEND_URL || '';
      if (!frontendUrl) {
        throw new Error(
          'HOME_HEALTH_AI_URL or FRONTEND_URL environment variable is required',
        );
      }

      const isProduction = process.env.NODE_ENV === 'production';
      const fragmentParams = new URLSearchParams({
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
        user: JSON.stringify(result.user),
      });
      const redirectUrl = `${frontendUrl}/auth/callback#${fragmentParams.toString()}`;

      reply.setCookie('accessToken', result.accessToken, {
        httpOnly: true,
        secure: isProduction,
        sameSite: 'strict',
        maxAge: 3600000,
        path: '/',
      });
      reply.setCookie('refreshToken', result.refreshToken, {
        httpOnly: true,
        secure: isProduction,
        sameSite: 'strict',
        maxAge: 604800000,
        path: '/',
      });

      reply.redirect(redirectUrl, 302);
    } catch (error: any) {
      reply.code(500).send({ 
        message: 'OAuth callback error', 
        error: error?.message || 'Unknown error' 
      });
    }
  });

  app.setGlobalPrefix(apiPrefix);
  if (apiPrefix && process.env.NODE_ENV === 'production') {
    console.warn(
      `API_PREFIX is set to "${apiPrefix}". GET /v1/api/blogs may 404; frontend expects /v1/api/blogs. Either unset API_PREFIX or ensure blog fallback routes registered.`,
    );
  }

  // Global validation pipe
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  app.useGlobalFilters(new HttpExceptionFilter());

  await app.register(require('@fastify/cookie'), {
    secret: process.env.COOKIE_SECRET || 'your-cookie-secret-key',
  });

  await app.register(require('@fastify/cors'), {
    origin: allowedOrigins.length > 0 ? allowedOrigins : false,
    credentials: true,
  });

  // Fallback: register job-management list + create directly on Fastify so they always exist
  const prefix = apiPrefix.replace(/^\//, '').replace(/\/$/, '');
  const jobMgmtBase = prefix ? `/${prefix}/job-management` : '/job-management';
  // Same path as blogs so proxies (e.g. /v1/api -> backend) and frontend can use one base URL
  const jobMgmtV1Base = '/v1/api/job-management';
  try {
    const jobService = app.get(JobManagementService);

    const handleGetPublicJobPostings = async (request: any, reply: any) => {
      try {
        const { search, page, limit } = request.query || {};
        const result = await jobService.findAllActive({
          search: search as string,
          page: page ? Number(page) : 1,
          limit: limit ? Number(limit) : 20,
        });
        return reply.send(SuccessHelper.createPaginatedResponse(result.data, result.total, result.page, result.limit));
      } catch (err: any) {
        const status = err?.statusCode || err?.status || 500;
        return reply.status(status).send({
          message: err?.message || 'Internal server error',
          error: err?.response?.message || err?.message,
          statusCode: status,
        });
      }
    };

    // Public: list all active job postings (careers page) – no auth
    fastifyInstance.get(`${jobMgmtBase}/job-postings`, handleGetPublicJobPostings);
    fastifyInstance.get(`${jobMgmtBase}/job-postings/`, handleGetPublicJobPostings);
    // Also under /v1/api/job-management/job-postings so it matches blogs (/v1/api/blogs) and works with proxies
    fastifyInstance.get(`${jobMgmtV1Base}/job-postings`, handleGetPublicJobPostings);
    fastifyInstance.get(`${jobMgmtV1Base}/job-postings/`, handleGetPublicJobPostings);

    fastifyInstance.get(`${jobMgmtBase}/organization/:organizationId/job-postings`, async (request: any, reply: any) => {
      try {
        const { organizationId } = request.params;
        const { search, status, page, limit } = request.query || {};
        const result = await jobService.findAllByOrganization(organizationId, {
          search: search as string,
          status: status as string,
          page: page ? Number(page) : 1,
          limit: limit ? Number(limit) : 20,
        });
        return reply.send(SuccessHelper.createPaginatedResponse(result.data, result.total, result.page, result.limit));
      } catch (err: any) {
        const status = err?.statusCode || err?.status || 500;
        return reply.status(status).send({
          message: err?.message || 'Internal server error',
          error: err?.response?.message || err?.message,
          statusCode: status,
        });
      }
    });

    fastifyInstance.post(`${jobMgmtBase}/organization/:organizationId/job-postings`, async (request: any, reply: any) => {
      try {
        const { organizationId } = request.params;
        const body = request.body;
        const result = await jobService.create(organizationId, body as any);
        return reply.status(201).send(SuccessHelper.createSuccessResponse(result, 'Job posting created successfully'));
      } catch (err: any) {
        const status = err?.statusCode || err?.status || 500;
        return reply.status(status).send({
          message: err?.message || 'Validation failed',
          error: err?.response?.message || err?.message,
          statusCode: status,
        });
      }
    });

    fastifyInstance.patch(`${jobMgmtBase}/organization/:organizationId/job-postings/:id`, async (request: any, reply: any) => {
      try {
        const { organizationId, id } = request.params;
        const body = (request.body || {}) as { status?: string };
        const result = await jobService.update(organizationId, id, body);
        return reply.send(SuccessHelper.createSuccessResponse(result, 'Job posting updated'));
      } catch (err: any) {
        const status = err?.statusCode || err?.status || 500;
        return reply.status(status).send({
          message: err?.message || 'Update failed',
          error: err?.response?.message || err?.message,
          statusCode: status,
        });
      }
    });

    fastifyInstance.delete(`${jobMgmtBase}/organization/:organizationId/job-postings/:id`, async (request: any, reply: any) => {
      try {
        const { organizationId, id } = request.params;
        await jobService.remove(organizationId, id);
        return reply.status(204).send();
      } catch (err: any) {
        const status = err?.statusCode || err?.status || 500;
        return reply.status(status).send({
          message: err?.message || 'Delete failed',
          error: err?.response?.message || err?.message,
          statusCode: status,
        });
      }
    });
  } catch (e) {
    console.warn('Job-management fallback routes not registered:', (e as Error).message);
  }

  // Blogs: ensure GET /v1/api/blogs always works (e.g. if API_PREFIX is set and double-prefixed controller path 404s)
  try {
    const blogService = app.get(BlogService);
    const handleGetBlogs = async (request: any, reply: any) => {
      try {
        const query = request.query || {};
        const page = query.page ? Number(query.page) : 1;
        const limit = query.limit ? Number(query.limit) : 10;
        const isPublished = query.is_published === 'false' || query.is_published === false ? false : true;
        const category = query.category as string | undefined;
        const search = query.search as string | undefined;
        const result = await blogService.findAll({
          page,
          limit,
          is_published: isPublished,
          category,
          search,
        });
        return reply.send(
          SuccessHelper.createPaginatedResponse(result.data, result.total, result.page, result.limit),
        );
      } catch (err: any) {
        const status = err?.statusCode || err?.status || 500;
        return reply.status(status).send({
          message: err?.message || 'Failed to fetch blogs',
          error: err?.response?.message || err?.message,
          statusCode: status,
        });
      }
    };
    fastifyInstance.get('/v1/api/blogs', handleGetBlogs);
    fastifyInstance.get('/v1/api/blogs/', handleGetBlogs);
    if (process.env.NODE_ENV === 'production') {
      console.log('Blogs fallback routes registered at GET /v1/api/blogs (production)');
    }
  } catch (e) {
    const errMsg = (e as Error).message;
    console.error(
      'Blogs fallback routes NOT registered. GET /v1/api/blogs will 404 unless API_PREFIX is empty and Nest controller is used. Error:',
      errMsg,
    );
  }

  const host = process.env.HOST || '0.0.0.0';
  await app.listen(appConfigService.port, host);
  const appUrl = process.env.HHBACKEND_URL || 
    (process.env.HOST && process.env.PORT
      ? `http://${process.env.HOST === '0.0.0.0' ? 'localhost' : process.env.HOST}:${process.env.PORT}`
      : `http://localhost:${appConfigService.port}`);
  // const wsUrl = process.env.WS_PORT
  //   ? `http://localhost:${process.env.WS_PORT}`
  //   : `http://localhost:${wsPort}`;
  // console.log(`Application is running on: ${appUrl}`);
  // console.log(`Referral WebSocket server on: ${wsUrl}/referrals`);
  console.log(`Application is running on: ${appUrl}`);
  console.log(`Referral WebSocket server on: ${wsUrl}/referrals`);

  const mcpPort = appConfigService.mcpPort;
  const mcpHandler = app.get(McpHttpHandlerService);
  const mcpAllowedOrigins =
    allowedOrigins.length > 0
      ? allowedOrigins
      : ['http://127.0.0.1:5173', 'http://localhost:5173'];
  const getMcpCorsHeaders = (origin: string | undefined) => {
    const allowOrigin =
      origin && mcpAllowedOrigins.includes(origin)
        ? origin
        : mcpAllowedOrigins[0];
    return {
      'Access-Control-Allow-Origin': allowOrigin,
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age': '86400',
    };
  };
  const mcpServer = http.createServer((req, res) => {
    const url = req.url ?? '/';
    const path = url.split('?')[0];
    const origin = req.headers.origin;
    const corsHeaders = getMcpCorsHeaders(origin);
    if (path === '/mcp') {
      if (req.method === 'OPTIONS') {
        res.writeHead(204, corsHeaders);
        res.end();
        return;
      }
      mcpHandler.handle(req, res, corsHeaders).catch((err) => {
        console.error('MCP handler error', err);
        if (!res.headersSent) {
          res.writeHead(500, { 'Content-Type': 'application/json', ...corsHeaders });
          res.end(JSON.stringify({ error: 'Internal server error' }));
        }
      });
    } else {
      res.writeHead(404, { 'Content-Type': 'application/json', ...corsHeaders });
      res.end(JSON.stringify({ error: 'Not Found' }));
    }
  });
  mcpServer.listen(mcpPort, host, () => {
    console.log(`MCP server listening on port ${mcpPort}`);
  });
}
bootstrap();
