import { NestFactory } from '@nestjs/core';
import { FastifyAdapter, NestFastifyApplication } from '@nestjs/platform-fastify';
import { ValidationPipe } from '@nestjs/common';
import * as http from 'node:http';
import { AppModule } from './app.module';

/** Shape of HTTP-like errors (Nest/Express) for fallback route handlers */
type HttpError = {
  statusCode?: number;
  status?: number;
  message?: string;
  response?: { message?: string };
};

function getErrPayload(
  err: unknown,
  defaultMessage: string,
): { message: string; error?: string; statusCode: number } {
  const e = err as HttpError;
  const status = e?.statusCode ?? e?.status ?? 500;
  return {
    message: (e?.message as string) || defaultMessage,
    error: e?.response?.message ?? e?.message,
    statusCode: status,
  };
}
import { AuthenticationModule } from './authentication/auth.module';
import { AppConfigService } from './config/app/config.service';
import { HttpExceptionFilter } from './common/exceptions/http-exception.filter';
import { AuthService } from './authentication/services/auth.service';
import { GoogleOAuthGuard } from './common/guards/google-oauth.guard';
import { SocketIoAdapter } from './common/adapters/socket-io.adapter';
import { JobManagementService } from './models/job-management/services/job-management.service';
import { BlogService } from './models/blog/services/blog.service';
import { SuccessHelper } from './common/helpers/responses/success.helper';
import { McpHttpHandlerService } from './mcp/mcp-http-handler.service';

async function bootstrap(): Promise<void> {
  const app = await NestFactory.create<NestFastifyApplication>(
    AppModule,
    new FastifyAdapter({ logger: true }),
  );

  const _httpPort = parseInt(process.env.PORT || '3000', 10);
  // const wsPort = parseInt(process.env.WS_PORT || String(httpPort + 1), 10);
  let allowedOrigins =
    process.env.ALLOWED_ORIGINS?.split(',')
      .map((o) => o.trim())
      .filter(Boolean) ||
    (process.env.HOME_HEALTH_AI_URL ? [process.env.HOME_HEALTH_AI_URL] : []) ||
    (process.env.FRONTEND_URL ? [process.env.FRONTEND_URL] : []);
  // Production fallback: allow live frontend so CORS works when ALLOWED_ORIGINS/FRONTEND_URL not set
  if (allowedOrigins.length === 0 && process.env.NODE_ENV === 'production') {
    allowedOrigins = ['https://homehealth.ai', 'https://www.homehealth.ai'];
  }
  app.useWebSocketAdapter(
    new SocketIoAdapter(app, allowedOrigins.length > 0 ? allowedOrigins : false),
  );

  const appConfigService = app.get(AppConfigService);
  const apiPrefix = appConfigService.apiPrefix;

  const fastifyInstance = app.getHttpAdapter().getInstance();

  // Health check at fixed path so production can verify this Nest app (with blogs) is the one serving api.homehealth.ai
  fastifyInstance.get(
    '/v1/api/health',
    (_request: unknown, reply: { send: (v: unknown) => void }) => {
      reply.send({
        ok: true,
        service: 'hh-backend',
        blogs: true,
        timestamp: new Date().toISOString(),
      });
    },
  );

  await fastifyInstance.register(require('@fastify/multipart'), {
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
    attachFieldsToBody: true, // so multipart create can read "data" field from body
  });

  await app.init();
  const moduleRef = app.select(AuthenticationModule);
  const authService = moduleRef.get(AuthService, { strict: false });
  const googleOAuthGuard = moduleRef.get(GoogleOAuthGuard, { strict: false });

  fastifyInstance.get(
    '/accounts/google/login/callback/',
    async (request: unknown, reply: unknown) => {
      const req = request as { user?: unknown };
      const rep = reply as {
        setHeader?: (n: string, v: string) => void;
        end?: (chunk?: unknown) => void;
        header: (n: string, v: string) => void;
        send: (c?: unknown) => void;
        code: (n: number) => { send: (c?: unknown) => void };
        setCookie: (name: string, value: string, opts: unknown) => void;
        redirect: (url: string, code: number) => void;
      };
      try {
        if (!rep.setHeader) {
          rep.setHeader = (name: string, value: string) => {
            rep.header(name, value);
          };
        }
        if (!rep.end) {
          rep.end = (chunk?: unknown) => {
            if (chunk) rep.send(chunk);
            else rep.send();
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
        } as import('@nestjs/common').ExecutionContext;

        // Run the Passport guard to authenticate
        const canActivate = await googleOAuthGuard.canActivate(context);
        if (!canActivate) {
          rep.code(401).send({ message: 'OAuth authentication failed' });
          return;
        }

        // Get authenticated user from request (set by Passport)
        const googleProfile = req.user;

        if (!googleProfile) {
          rep.code(401).send({ message: 'OAuth authentication incomplete' });
          return;
        }

        // Process OAuth login (Passport sets request.user to the Google profile shape)
        const result = await authService.googleLogin(
          googleProfile as {
            googleId: string;
            email: string;
            firstName: string;
            lastName: string;
            picture?: string;
          },
        );

        const frontendUrl = process.env.HOME_HEALTH_AI_URL || process.env.FRONTEND_URL || '';
        if (!frontendUrl) {
          throw new Error('HOME_HEALTH_AI_URL or FRONTEND_URL environment variable is required');
        }

        const isProduction = process.env.NODE_ENV === 'production';
        const fragmentParams = new URLSearchParams({
          accessToken: result.accessToken,
          refreshToken: result.refreshToken,
          user: JSON.stringify(result.user),
        });
        const redirectUrl = `${frontendUrl}/auth/callback#${fragmentParams.toString()}`;

        rep.setCookie('accessToken', result.accessToken, {
          httpOnly: true,
          secure: isProduction,
          sameSite: 'strict',
          maxAge: 3600000,
          path: '/',
        });
        rep.setCookie('refreshToken', result.refreshToken, {
          httpOnly: true,
          secure: isProduction,
          sameSite: 'strict',
          maxAge: 604800000,
          path: '/',
        });

        rep.redirect(redirectUrl, 302);
      } catch (error: unknown) {
        const msg = (error as { message?: string })?.message ?? 'Unknown error';
        rep.code(500).send({
          message: 'OAuth callback error',
          error: msg,
        });
      }
    },
  );

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

  // Fallback: register job-management routes only when API_PREFIX is set. When empty, AppController and JobManagementController already serve /job-management/... and /v1/api/job-management/...
  const prefix = apiPrefix.replace(/^\//, '').replace(/\/$/, '');
  const jobMgmtBase = prefix ? `/${prefix}/job-management` : '/job-management';
  const jobMgmtV1Base = '/v1/api/job-management';
  const registerJobMgmtFallbacks = !!prefix;
  if (registerJobMgmtFallbacks) {
  try {
    const jobService = app.get(JobManagementService);

    const handleGetPublicJobPostings = async (request: unknown, reply: unknown) => {
      const req = request as { query?: { search?: string; page?: string; limit?: string } };
      const rep = reply as {
        send: (v: unknown) => void;
        code: (n: number) => { send: (v: unknown) => void };
      };
      try {
        const q = req.query || {};
        const result = await jobService.findAllActive({
          search: q.search,
          page: q.page ? Number(q.page) : 1,
          limit: q.limit ? Number(q.limit) : 20,
        });
        return rep.send(
          SuccessHelper.createPaginatedResponse(
            result.data,
            result.total,
            result.page,
            result.limit,
          ),
        );
      } catch (err: unknown) {
        const payload = getErrPayload(err, 'Internal server error');
        return rep.code(payload.statusCode).send(payload);
      }
    };

    // Public: get merged application form for a job (org + job-specific fields) – apply page
    const handleGetJobApplicationForm = async (request: unknown, reply: unknown) => {
      const req = request as { params?: { id?: string } };
      const rep = reply as {
        send: (v: unknown) => void;
        code: (n: number) => { send: (v: unknown) => void };
      };
      try {
        const id = req.params?.id;
        if (!id) return rep.code(400).send({ message: 'Missing id', statusCode: 400 });
        const form = await jobService.getApplicationFormForJob(id);
        return rep.send(SuccessHelper.createSuccessResponse(form, 'Application form retrieved'));
      } catch (err: unknown) {
        const payload = getErrPayload(err, 'Job not found');
        return rep.code(payload.statusCode).send(payload);
      }
    };
    fastifyInstance.get(
      `${jobMgmtBase}/job-postings/:id/application-form`,
      handleGetJobApplicationForm,
    );
    fastifyInstance.get(
      `${jobMgmtV1Base}/job-postings/:id/application-form`,
      handleGetJobApplicationForm,
    );

    // Public: get one active job by id with organization (apply page) – no auth
    const handleGetPublicJobPostingById = async (request: unknown, reply: unknown) => {
      const req = request as { params?: { id?: string } };
      const rep = reply as {
        send: (v: unknown) => void;
        code: (n: number) => { send: (v: unknown) => void };
      };
      try {
        const id = req.params?.id;
        if (!id) return rep.code(400).send({ message: 'Missing id', statusCode: 400 });
        const job = await jobService.findOneByIdPublic(id);
        return rep.send(SuccessHelper.createSuccessResponse(job, 'Job posting retrieved'));
      } catch (err: unknown) {
        const payload = getErrPayload(err, 'Job not found');
        return rep.code(payload.statusCode).send(payload);
      }
    };
    fastifyInstance.get(`${jobMgmtBase}/job-postings/:id`, handleGetPublicJobPostingById);
    fastifyInstance.get(`${jobMgmtV1Base}/job-postings/:id`, handleGetPublicJobPostingById);

    // Public: list all active job postings (careers page) – no auth
    fastifyInstance.get(`${jobMgmtBase}/job-postings`, handleGetPublicJobPostings);
    fastifyInstance.get(`${jobMgmtBase}/job-postings/`, handleGetPublicJobPostings);
    fastifyInstance.get(`${jobMgmtV1Base}/job-postings`, handleGetPublicJobPostings);
    fastifyInstance.get(`${jobMgmtV1Base}/job-postings/`, handleGetPublicJobPostings);

    const handleGetOrgJobPostings = async (request: unknown, reply: unknown) => {
      const req = request as {
        params?: { organizationId?: string };
        query?: { search?: string; status?: string; page?: string; limit?: string };
      };
      const rep = reply as {
        send: (v: unknown) => void;
        code: (n: number) => { send: (v: unknown) => void };
      };
      try {
        const organizationId = req.params?.organizationId;
        if (!organizationId)
          return rep.code(400).send({ message: 'Missing organizationId', statusCode: 400 });
        const q = req.query || {};
        const result = await jobService.findAllByOrganization(organizationId, {
          search: q.search,
          status: q.status,
          page: q.page ? Number(q.page) : 1,
          limit: q.limit ? Number(q.limit) : 20,
        });
        return rep.send(
          SuccessHelper.createPaginatedResponse(
            result.data,
            result.total,
            result.page,
            result.limit,
          ),
        );
      } catch (err: unknown) {
        const payload = getErrPayload(err, 'Internal server error');
        return rep.code(payload.statusCode).send(payload);
      }
    };
    fastifyInstance.get(
      `${jobMgmtBase}/organization/:organizationId/job-postings`,
      handleGetOrgJobPostings,
    );
    fastifyInstance.get(
      `${jobMgmtV1Base}/organization/:organizationId/job-postings`,
      handleGetOrgJobPostings,
    );

    const handleCreateJobPosting = async (request: unknown, reply: unknown) => {
      const req = request as {
        params?: { organizationId?: string };
        body?: import('./models/job-management/dto/create-job-posting.dto').CreateJobPostingDto;
      };
      const rep = reply as {
        code: (n: number) => { send: (v: unknown) => void };
        send: (v: unknown) => void;
      };
      try {
        const organizationId = req.params?.organizationId;
        if (!organizationId)
          return rep.code(400).send({ message: 'Missing organizationId', statusCode: 400 });
        const body = req.body;
        if (!body) return rep.code(400).send({ message: 'Missing body', statusCode: 400 });
        const result = await jobService.create(organizationId, body);
        return rep
          .code(201)
          .send(SuccessHelper.createSuccessResponse(result, 'Job posting created successfully'));
      } catch (err: unknown) {
        const payload = getErrPayload(err, 'Validation failed');
        return rep.code(payload.statusCode).send(payload);
      }
    };
    fastifyInstance.post(
      `${jobMgmtBase}/organization/:organizationId/job-postings`,
      handleCreateJobPosting,
    );
    fastifyInstance.post(
      `${jobMgmtV1Base}/organization/:organizationId/job-postings`,
      handleCreateJobPosting,
    );

    const handlePatchJobPosting = async (request: any, reply: any) => {
      try {
        const { organizationId, id } = request.params;
        const body = (request.body || {}) as { status?: string };
        const result = await jobService.update(organizationId, id, body);
        return reply.send(SuccessHelper.createSuccessResponse(result, 'Job posting updated'));
      } catch (err: any) {
        const status = err?.statusCode || err?.status || 500;
        return reply.code(status).send({
          message: err?.message || 'Update failed',
          error: err?.response?.message || err?.message,
          statusCode: status,
        });
      }
    };
    fastifyInstance.patch(
      `${jobMgmtBase}/organization/:organizationId/job-postings/:id`,
      handlePatchJobPosting,
    );
    fastifyInstance.patch(
      `${jobMgmtV1Base}/organization/:organizationId/job-postings/:id`,
      handlePatchJobPosting,
    );

    const handleDeleteJobPosting = async (request: unknown, reply: unknown) => {
      const req = request as { params?: { organizationId?: string; id?: string } };
      const rep = reply as {
        code: (n: number) => { send: (v?: unknown) => void };
        send: (v: unknown) => void;
      };
      try {
        const organizationId = req.params?.organizationId;
        const id = req.params?.id;
        if (!organizationId || !id)
          return rep.code(400).send({ message: 'Missing organizationId or id', statusCode: 400 });
        await jobService.remove(organizationId, id);
        return rep.code(204).send(undefined);
      } catch (err: unknown) {
        const payload = getErrPayload(err, 'Delete failed');
        return rep.code(payload.statusCode).send(payload);
      }
    };
    fastifyInstance.delete(
      `${jobMgmtBase}/organization/:organizationId/job-postings/:id`,
      handleDeleteJobPosting,
    );
    fastifyInstance.delete(
      `${jobMgmtV1Base}/organization/:organizationId/job-postings/:id`,
      handleDeleteJobPosting,
    );

    // Public: submit job application (apply form) – no auth
    const handleCreateJobApplication = async (request: unknown, reply: unknown) => {
      const req = request as { body?: Record<string, unknown> };
      const rep = reply as {
        code: (n: number) => { send: (v: unknown) => void };
        send: (v: unknown) => void;
      };
      try {
        const body =
          (req.body as {
            job_posting_id?: string;
            applicant_name?: string;
            applicant_email?: string;
            applicant_phone?: string;
            notes?: string;
            submitted_fields?: Record<string, unknown>;
          }) || {};
        if (!body.job_posting_id || !body.applicant_name || !body.applicant_email) {
          return rep.code(400).send({
            message: 'job_posting_id, applicant_name, and applicant_email are required',
            statusCode: 400,
          });
        }
        const result = await jobService.createApplication({
          job_posting_id: body.job_posting_id,
          applicant_name: body.applicant_name,
          applicant_email: body.applicant_email,
          applicant_phone: body.applicant_phone,
          notes: body.notes,
          submitted_fields: body.submitted_fields,
        });
        return rep
          .code(201)
          .send(SuccessHelper.createSuccessResponse(result, 'Application submitted'));
      } catch (err: unknown) {
        const payload = getErrPayload(err, 'Failed to submit application');
        return rep.code(payload.statusCode).send(payload);
      }
    };
    // Application form fields: GET (public) and PATCH (org admin) – so setup page and apply form work even if controller 404s
    const handleGetApplicationFormFields = async (request: unknown, reply: unknown) => {
      const req = request as { params?: { organizationId?: string } };
      const rep = reply as {
        send: (v: unknown) => void;
        code: (n: number) => { send: (v: unknown) => void };
      };
      try {
        const organizationId = req.params?.organizationId;
        if (!organizationId)
          return rep.code(400).send({ message: 'Missing organizationId', statusCode: 400 });
        const fields = await jobService.getApplicationFormFields(organizationId);
        return rep.send(SuccessHelper.createSuccessResponse(fields));
      } catch (err: unknown) {
        const payload = getErrPayload(err, 'Failed to load application form fields');
        return rep.code(payload.statusCode).send(payload);
      }
    };
    const handlePatchApplicationFormFields = async (request: unknown, reply: unknown) => {
      const req = request as {
        params?: { organizationId?: string };
        body?: { fields?: unknown[] };
      };
      const rep = reply as {
        send: (v: unknown) => void;
        code: (n: number) => { send: (v: unknown) => void };
      };
      try {
        const organizationId = req.params?.organizationId;
        if (!organizationId)
          return rep.code(400).send({ message: 'Missing organizationId', statusCode: 400 });
        const fields = Array.isArray(req.body?.fields) ? req.body.fields : [];
        const result = await jobService.setApplicationFormFields(
          organizationId,
          fields as Record<string, unknown>[],
        );
        return rep.send(
          SuccessHelper.createSuccessResponse(result, 'Application form fields saved'),
        );
      } catch (err: unknown) {
        const payload = getErrPayload(err, 'Failed to save application form fields');
        return rep.code(payload.statusCode).send(payload);
      }
    };
    const appFormPath = '/organization/:organizationId/application-form/fields';
    fastifyInstance.get(`${jobMgmtBase}${appFormPath}`, handleGetApplicationFormFields);
    fastifyInstance.get(`${jobMgmtBase}${appFormPath}/`, handleGetApplicationFormFields);
    fastifyInstance.get(`${jobMgmtV1Base}${appFormPath}`, handleGetApplicationFormFields);
    fastifyInstance.get(`${jobMgmtV1Base}${appFormPath}/`, handleGetApplicationFormFields);
    fastifyInstance.patch(`${jobMgmtBase}${appFormPath}`, handlePatchApplicationFormFields);
    fastifyInstance.patch(`${jobMgmtBase}${appFormPath}/`, handlePatchApplicationFormFields);
    fastifyInstance.patch(`${jobMgmtV1Base}${appFormPath}`, handlePatchApplicationFormFields);
    fastifyInstance.patch(`${jobMgmtV1Base}${appFormPath}/`, handlePatchApplicationFormFields);

    fastifyInstance.post(`${jobMgmtBase}/job-applications`, handleCreateJobApplication);
    fastifyInstance.post(`${jobMgmtBase}/job-applications/`, handleCreateJobApplication);
    // POST /v1/api/job-management/job-applications is handled by JobManagementController (do not duplicate here)
    // Also register /api/job-management/job-applications (no v1) for frontend/proxies that use this path
    fastifyInstance.post('/api/job-management/job-applications', handleCreateJobApplication);
    fastifyInstance.post('/api/job-management/job-applications/', handleCreateJobApplication);
  } catch (e) {
    console.warn('Job-management fallback routes not registered:', (e as Error).message); // allowed
  }
  }

  // Blogs: only register GET /v1/api/blogs when API_PREFIX is set (otherwise Nest BlogController already serves it and we'd get "Method already declared")
  const registerV1BlogsRoute = !!prefix;
  if (registerV1BlogsRoute) {
    try {
      const blogService = app.get(BlogService);
      const handleGetBlogs = async (request: unknown, reply: unknown) => {
      const req = request as {
        query?: {
          page?: string;
          limit?: string;
          is_published?: string | boolean;
          category?: string;
          search?: string;
        };
      };
      const rep = reply as {
        send: (v: unknown) => void;
        code: (n: number) => { send: (v: unknown) => void };
      };
      try {
        const query = req.query || {};
        const page = query.page ? Number(query.page) : 1;
        const limit = query.limit ? Number(query.limit) : 10;
        const isPublished =
          query.is_published === 'false' || query.is_published === false ? false : true;
        const result = await blogService.findAll({
          page,
          limit,
          is_published: isPublished,
          category: query.category,
          search: query.search,
        });
        return rep.send(
          SuccessHelper.createPaginatedResponse(
            result.data,
            result.total,
            result.page,
            result.limit,
          ),
        );
      } catch (err: unknown) {
        const payload = getErrPayload(err, 'Failed to fetch blogs');
        return rep.code(payload.statusCode).send(payload);
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
  }

  const host = process.env.HOST || '0.0.0.0';
  await app.listen(appConfigService.port, host);
  const appUrl =
    process.env.HHBACKEND_URL ||
    (process.env.HOST && process.env.PORT
      ? `http://${process.env.HOST === '0.0.0.0' ? 'localhost' : process.env.HOST}:${process.env.PORT}`
      : `http://localhost:${appConfigService.port}`);
  // const wsUrl = process.env.WS_PORT
  //   ? `http://localhost:${process.env.WS_PORT}`
  //   : `http://localhost:${wsPort}`;

  console.log(`Application is running on: ${appUrl}`);

  console.log(`Referral WebSocket server on: ${appUrl}/referrals`);

  const mcpPort = appConfigService.mcpPort;
  const mcpHandler = app.get(McpHttpHandlerService);
  const mcpAllowedOrigins =
    allowedOrigins.length > 0 ? allowedOrigins : ['http://127.0.0.1:5173', 'http://localhost:5173'];
  const getMcpCorsHeaders = (origin: string | undefined): Record<string, string> => {
    const allowOrigin =
      origin && mcpAllowedOrigins.includes(origin) ? origin : mcpAllowedOrigins[0];
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
      mcpHandler.handle(req, res, corsHeaders).catch((err: unknown) => {
        console.error('MCP handler error', err); // allowed
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
void bootstrap();
