import { NestFactory } from '@nestjs/core';
import { FastifyAdapter, NestFastifyApplication } from '@nestjs/platform-fastify';
import { ValidationPipe } from '@nestjs/common';
import { AppModule } from './app.module';
import { AuthenticationModule } from './authentication/auth.module';
import { AppConfigService } from './config/app/config.service';
import { HttpExceptionFilter } from './common/exceptions/http-exception.filter';
import { AuthService } from './authentication/services/auth.service';
import { GoogleOAuthGuard } from './common/guards/google-oauth.guard';
import { SocketIoAdapter } from './common/adapters/socket-io.adapter';

async function bootstrap() {
  const app = await NestFactory.create<NestFastifyApplication>(AppModule, new FastifyAdapter({logger: false}));

  const httpPort = parseInt(process.env.PORT || '3000', 10);
  const wsPort = parseInt(process.env.WS_PORT || String(httpPort + 1), 10);
  const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') ||
    (process.env.HOME_HEALTH_AI_URL ? [process.env.HOME_HEALTH_AI_URL] : []) ||
    (process.env.FRONTEND_URL ? [process.env.FRONTEND_URL] : []);
  app.useWebSocketAdapter(new SocketIoAdapter(app, wsPort, allowedOrigins.length > 0 ? allowedOrigins : false));

  const appConfigService = app.get(AppConfigService);

  const fastifyInstance = app.getHttpAdapter().getInstance();
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

  app.setGlobalPrefix(appConfigService.apiPrefix);

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

  const host = process.env.HOST || '0.0.0.0';
  await app.listen(appConfigService.port, host);
  const appUrl = process.env.HHBACKEND_URL || 
    (process.env.HOST && process.env.PORT
      ? `http://${process.env.HOST === '0.0.0.0' ? 'localhost' : process.env.HOST}:${process.env.PORT}`
      : `http://localhost:${appConfigService.port}`);
  const wsUrl = process.env.WS_PORT
    ? `http://localhost:${process.env.WS_PORT}`
    : `http://localhost:${wsPort}`;
  console.log(`Application is running on: ${appUrl}`);
  console.log(`Referral WebSocket server on: ${wsUrl}/referrals`);
}
bootstrap();
