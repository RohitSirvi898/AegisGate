import http, { ServerResponse } from 'node:http';
import https from 'node:https';

import cors from 'cors';
import dotenv from 'dotenv';
import express, { type NextFunction, type Request, type Response } from 'express';
import { createProxyMiddleware, fixRequestBody, type Options } from 'http-proxy-middleware';
import mongoose from 'mongoose';

import { initQueue } from './config/queue.js';
import { redisClient } from './config/redis.js';
import { authenticateAndAuthorize } from './middleware/authenticate.js';
import {
  createCircuitBreakerMiddleware,
  extractOrigin,
  handleProxyError,
  UPSTREAM_TIMEOUT_MS
} from './middleware/circuitBreaker.js';
import { ipJailMiddleware } from './middleware/ipJail.js';
import { rateLimiter } from './middleware/rateLimiter.js';
import { createResponseCacheMiddleware } from './middleware/responseCache.js';
import { securityFilter } from './middleware/securityFilter.js';
import { ProjectModel } from './models/project.js';
import { adminRouter } from './routes/admin.js';
import { analyticsRouter } from './routes/analytics.js';
import { authRouter } from './routes/auth.js';
import { projectsRouter } from './routes/projects.js';
import { usersRouter } from './routes/users.js';
import { getOrSetRequestId, requestIdMiddleware, sendGatewayError } from './utils/errors.js';
import { getClientIp } from './utils/ip.js';
import { getSsrfSafeAgent, ssrfHttpAgent, ssrfHttpsAgent, validateTargetUrl } from './utils/ssrf.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 8080;

http.globalAgent = ssrfHttpAgent;
https.globalAgent = ssrfHttpsAgent;

app.use(cors({
  exposedHeaders: ['Retry-After', 'X-Request-Id', 'X-Shielded-By']
}));

app.use(requestIdMiddleware);

app.use((req: Request, res: Response, next: NextFunction): void => {
  const rawLength = req.headers['content-length'];
  if (rawLength) {
    const length = parseInt(rawLength, 10);
    if (!isNaN(length) && length > 100 * 1024) {
      sendGatewayError(res, 413, 'payload_too_large', req);
      return;
    }
  }
  next();
});

app.use(express.json({
  limit: '100kb',
  verify: (req: any, _res, buf) => {
    req.rawBody = buf.toString();
  }
}));

app.use((err: any, req: Request, res: Response, next: NextFunction): void => {
  if (err && (err.type === 'entity.too.large' || err.status === 413 || err.statusCode === 413)) {
    sendGatewayError(res, 413, 'payload_too_large', req);
    return;
  }
  next(err);
});

app.use((req: Request, _res: Response, next: NextFunction): void => {
  (req as any).clientIp = getClientIp(req);
  next();
});

app.use(ipJailMiddleware);
app.use(rateLimiter);

app.use('/api/v1/auth', authRouter);
app.use('/api/v1/projects', projectsRouter);
app.use('/api/v1/analytics', analyticsRouter);
app.use('/api/v1/users', usersRouter);
app.use('/api/v1/admin', adminRouter);

const routesConfig = [
  {
    path: '/api/v1/users',
    target: 'http://httpbin.org/anything/users',
    roles: ['admin', 'developer', 'user']
  },
  {
    path: '/api/v1/payments',
    target: 'http://httpbin.org/anything/payments',
    roles: ['admin']
  }
];

routesConfig.forEach(({ path, target, roles }) => {
  if (path === '/api/v1/users') {
    return;
  }

  const origin = extractOrigin(target);

  const proxyOptions: Options = {
    target,
    changeOrigin: true,
    agent: getSsrfSafeAgent(target),
    timeout: UPSTREAM_TIMEOUT_MS,
    proxyTimeout: UPSTREAM_TIMEOUT_MS,
    pathRewrite: { [`^${path}`]: '' },
    on: {
      error: (err, req, res) => {
        handleProxyError(err, req as Request, res as ServerResponse, origin || undefined);
      },
      proxyReq: (proxyReq, req, _res) => {
        proxyReq.setHeader('X-Request-Id', (req as any).requestId || getOrSetRequestId(req as Request));
        proxyReq.setHeader('X-Shielded-By', 'AegisGate-Core');
        fixRequestBody(proxyReq, req);
      }
    }
  };

  app.use(
    path,
    (req: Request, _res: Response, next: NextFunction) => {
      (req as any).targetUrl = target;
      next();
    },
    authenticateAndAuthorize(roles),
    securityFilter,
    createResponseCacheMiddleware(),
    createCircuitBreakerMiddleware(),
    createProxyMiddleware(proxyOptions)
  );
});

// Resolves tenant configuration by API key with Redis caching and SSRF validation
const dynamicTargetResolver = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  const apiKey = req.headers['x-aegis-api-key'];

  if (!apiKey || typeof apiKey !== 'string' || apiKey.trim() === '') {
    sendGatewayError(res, 401, 'invalid_or_missing_credentials', req);
    return;
  }

  const cleanApiKey = apiKey.trim();
  let targetUrl: string | null = null;
  let dryRun = true;
  let enableLLMAudit = true;
  let slackWebhookUrl = '';
  let discordWebhookUrl = '';
  let projectId: string | null = null;
  let routes: any[] = [];

  try {
    const cached = await redisClient.get(`project:${cleanApiKey}`);
    if (cached) {
      try {
        const parsed = JSON.parse(cached);
        targetUrl = parsed.targetUrl || parsed.target || null;
        dryRun = typeof parsed.dryRun === 'boolean' ? parsed.dryRun : true;
        enableLLMAudit = typeof parsed.enableLLMAudit === 'boolean' ? parsed.enableLLMAudit : true;
        slackWebhookUrl = parsed.slackWebhookUrl || '';
        discordWebhookUrl = parsed.discordWebhookUrl || '';
        projectId = parsed.projectId || null;
        routes = parsed.routes || [];
      } catch {
        targetUrl = cached;
      }
    }

    if (!targetUrl) {
      const project = await ProjectModel.findOne({ apiKey: cleanApiKey });
      if (!project) {
        sendGatewayError(res, 401, 'invalid_or_missing_credentials', req);
        return;
      }

      targetUrl = project.targetUrl || process.env.UPSTREAM_TARGET_URL || null;
      dryRun = project.dryRun ?? true;
      enableLLMAudit = project.enableLLMAudit ?? true;
      slackWebhookUrl = project.slackWebhookUrl || '';
      discordWebhookUrl = project.discordWebhookUrl || '';
      projectId = project._id.toString();

      if (!targetUrl) {
        sendGatewayError(res, 503, 'upstream_unavailable', req);
        return;
      }

      const cachePayload = JSON.stringify({
        targetUrl,
        dryRun,
        enableLLMAudit,
        slackWebhookUrl,
        discordWebhookUrl,
        projectId,
        projectName: project.projectName
      });

      try {
        await redisClient.setex(`project:${cleanApiKey}`, 300, cachePayload);
      } catch (redisErr: any) {
        console.error('[Redis Cache Set Error] Failed to cache project mapping:', redisErr.message);
      }
    }

    const ssrfCheck = validateTargetUrl(targetUrl);
    if (!ssrfCheck.valid) {
      console.warn(`[SSRF Guard Rejected Target] ${targetUrl}: ${ssrfCheck.reason}`);
      sendGatewayError(res, 503, 'upstream_unavailable', req);
      return;
    }

    const currentPath = req.path;
    const matchingRoute = routes.find((r: any) => {
      if (!r.pathPattern) return false;
      return currentPath === r.pathPattern || currentPath.startsWith(r.pathPattern.replace(/\*$/, ''));
    });

    (req as any).targetUrl = targetUrl;
    (req as any).projectId = projectId;
    (req as any).dryRun = dryRun;
    (req as any).enableLLMAudit = enableLLMAudit;
    (req as any).slackWebhookUrl = slackWebhookUrl;
    (req as any).discordWebhookUrl = discordWebhookUrl;
    if (matchingRoute) {
      (req as any).routeConfig = matchingRoute;
      (req as any).routeCache = matchingRoute.cache;
      (req as any).routeId = matchingRoute.id || matchingRoute.pathPattern;
    }

    next();
  } catch (error: any) {
    console.error('[Dynamic Target Resolution Error]:', error?.message || error);
    sendGatewayError(res, 503, 'upstream_unavailable', req);
    return;
  }
};

app.use(
  '/',
  dynamicTargetResolver,
  securityFilter,
  createResponseCacheMiddleware(),
  createCircuitBreakerMiddleware(),
  createProxyMiddleware({
    router: async (req) => {
      return (req as any).targetUrl || process.env.UPSTREAM_TARGET_URL;
    },
    changeOrigin: true,
    secure: false,
    xfwd: true,
    timeout: UPSTREAM_TIMEOUT_MS,
    proxyTimeout: UPSTREAM_TIMEOUT_MS,
    on: {
      proxyReq: (proxyReq, req, _res) => {
        proxyReq.removeHeader('x-aegis-api-key');
        proxyReq.setHeader('X-Request-Id', (req as any).requestId || getOrSetRequestId(req as Request));
        proxyReq.setHeader('X-Shielded-By', 'AegisGate-Core');
        fixRequestBody(proxyReq, req);
      },
      error: (err, req, res) => {
        handleProxyError(err, req as Request, res as ServerResponse);
      }
    }
  })
);

app.use((req: Request, res: Response): void => {
  const requestId = getOrSetRequestId(req, res);
  res.status(404).json({
    error: 'not_found',
    requestId
  });
});

app.listen(PORT, async () => {
  console.log(`=================================================`);
  console.log(`🛡️  AegisGate Core Proxy Server running on port: ${PORT}`);
  console.log(`🔐 Dynamic SaaS Multi-Tenant Routing & Edge Auth Engaged`);
  console.log(`⚡ PRD v2.1 Hardened Pipeline Active`);
  console.log(`=================================================`);

  const MONGO_URI = process.env.MONGO_URI || '';
  if (MONGO_URI) {
    try {
      await mongoose.connect(MONGO_URI);
      console.log('💾 Connected to MongoDB dedicated AegisGate database.');
    } catch (err: any) {
      console.error('❌ Failed to connect to MongoDB in Gateway Core:', err.message);
    }
  }

  await initQueue();
});