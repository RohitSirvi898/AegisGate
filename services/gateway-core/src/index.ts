import express, { type Request, type Response, type NextFunction } from 'express';
import { createProxyMiddleware, fixRequestBody, type Options } from 'http-proxy-middleware';
import dotenv from 'dotenv';
import { ServerResponse } from 'http';
import cors from 'cors';
import mongoose from 'mongoose';
import { rateLimiter } from './middleware/rateLimiter.js';
import { authenticateAndAuthorize } from './middleware/authenticate.js';
import { aiFirewall } from './middleware/aiFirewall.js';
import { initQueue } from './config/queue.js';
import { authRouter } from './routes/auth.js';
import { projectsRouter } from './routes/projects.js';
import { analyticsRouter } from './routes/analytics.js';
import { usersRouter } from './routes/users.js';
import { redisClient } from './config/redis.js';
import { ProjectModel } from './models/project.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 8080;
const AI_ANOMALY_ENGINE_URL = process.env.AI_ANOMALY_ENGINE_URL || 'http://localhost:8000/analyze';

// Enable CORS globally to support frontend calls
app.use(cors());

// Enable express.json body parser globally with rawBody verification capture
app.use(express.json({
    verify: (req: any, res, buf) => {
        req.rawBody = buf.toString();
    }
}));

// Apply global DDoS firewall log rate metrics across all entries
app.use(rateLimiter);

/**
 * Dedicated Asynchronous Telemetry Logging Middleware.
 * Captures request footprints and sends telemetry data to the Python AI Anomaly Engine.
 */
const telemetryLogger = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const pathLength = (req.originalUrl || req.url || '').length;
    const methodLength = (req.method || '').length;
    const timestampFraction = (Date.now() % 10000) / 10000;
    const contentLength = Number(req.headers['content-length']) || 0;

    // Nest numerical features inside the 'metrics' field required by PayloadMetrics schema
    const telemetryPayload = {
        metrics: [
            pathLength / 100.0,          // Normalized path length feature
            methodLength / 10.0,         // Normalized HTTP method length feature
            timestampFraction,           // Time-based periodic feature
            contentLength / 1000.0       // Normalized content length feature
        ]
    };

    // Asynchronous fire-and-forget background HTTP call to AI Anomaly Engine uvicorn server
    // Guided by an absolute Fail-Open Policy to ensure it never delays or drops user responses
    fetch(AI_ANOMALY_ENGINE_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(telemetryPayload)
    }).catch((err) => {
        console.error('[Telemetry Fail-Open Bypass] Silently bypassed anomaly engine exception:', (err as Error).message);
    });

    next();
};

// Apply telemetry logger globally upstream of the routing pipeline
app.use(telemetryLogger);

// Mount stateless IAM authentication routes
app.use('/api/v1/auth', authRouter);

// Mount modular sub-routers
app.use('/api/v1/projects', projectsRouter);
app.use('/api/v1/analytics', analyticsRouter);
app.use('/api/v1/users', usersRouter);

// Target downstream configurations mapped to their explicit protection rules
const routesConfig = [
    {
        path: '/api/v1/users',
        target: 'http://httpbin.org/anything/users',
        roles: ['admin', 'developer', 'user'] // Public/General data bounds
    },
    {
        path: '/api/v1/payments',
        target: 'http://httpbin.org/anything/payments',
        roles: ['admin'] // Highly critical administrative route
    }
];

// Register dynamic proxies coupled with identity firewall checkpoints
routesConfig.forEach(({ path, target, roles }) => {
    // Skip /api/v1/users proxy configuration to prioritize the native controller route
    if (path === '/api/v1/users') {
        return;
    }

    const proxyOptions: Options = {
        target,
        changeOrigin: true,
        pathRewrite: { [`^${path}`]: '' },
        on: {
            error: (err, req, res) => {
                if (res instanceof ServerResponse && !res.headersSent) {
                    res.writeHead(502, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Bad Gateway', message: 'Upstream service unreachable.' }));
                }
            },
            proxyReq: (proxyReq, req, res) => {
                proxyReq.setHeader('X-Shielded-By', 'AegisGate-Core');
                fixRequestBody(proxyReq, req);
            }
        }
    };

    // Secure path execution wrapper: [Rate Limit] -> [JWT/RBAC Check] -> [AI Firewall] -> [Proxy Stream Forwarding]
    app.use(path, authenticateAndAuthorize(roles), aiFirewall, createProxyMiddleware(proxyOptions));
});

/**
 * Dynamic Upstream Target Resolver Middleware.
 * Inspects incoming x-aegis-api-key header, queries Redis (project:<api_key>),
 * falls back to MongoDB with a 5-minute TTL cache, and resolves the project targetUrl.
 * Returns HTTP 401 Unauthorized JSON response if API key is missing or invalid.
 */
const dynamicTargetResolver = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const apiKey = req.headers['x-aegis-api-key'];

    if (!apiKey || typeof apiKey !== 'string' || apiKey.trim() === '') {
        res.status(401).json({
            error: 'Unauthorized',
            message: 'API key is missing or invalid.'
        });
        return;
    }

    const cleanApiKey = apiKey.trim();
    let targetUrl: string | null = null;
    let dryRun = true;
    let enableLLMAudit = true;
    let slackWebhookUrl = '';
    let discordWebhookUrl = '';
    let projectId: string | null = null;

    try {
        // Query Redis cache for project mapping: project:<api_key>
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
            } catch {
                targetUrl = cached;
            }
        }

        // Cache miss in Redis -> fetch from MongoDB
        if (!targetUrl) {
            const project = await ProjectModel.findOne({ apiKey: cleanApiKey });
            if (!project) {
                res.status(401).json({
                    error: 'Unauthorized',
                    message: 'API key is missing or invalid.'
                });
                return;
            }

            targetUrl = project.targetUrl || process.env.UPSTREAM_TARGET_URL || null;
            dryRun = project.dryRun ?? true;
            enableLLMAudit = project.enableLLMAudit ?? true;
            slackWebhookUrl = project.slackWebhookUrl || '';
            discordWebhookUrl = project.discordWebhookUrl || '';
            projectId = project._id.toString();

            if (!targetUrl) {
                res.status(401).json({
                    error: 'Unauthorized',
                    message: 'No target URL configured for this project.'
                });
                return;
            }

            // Cache in Redis with 5-minute (300 seconds) TTL
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

        // Attach resolved target URL and metadata onto request object for proxy and firewall
        (req as any).targetUrl = targetUrl;
        (req as any).projectId = projectId;
        (req as any).dryRun = dryRun;
        (req as any).enableLLMAudit = enableLLMAudit;
        (req as any).slackWebhookUrl = slackWebhookUrl;
        (req as any).discordWebhookUrl = discordWebhookUrl;

        next();
    } catch (error: any) {
        console.error('[Dynamic Target Resolution Error]:', error?.message || error);
        res.status(500).json({
            error: 'Internal Server Error',
            message: 'Error resolving dynamic project target.'
        });
        return;
    }
};

// Any route that is NOT an internal AegisGate route falls down into this dynamic multi-tenant SaaS proxy
app.use(
    '/',
    dynamicTargetResolver,
    aiFirewall, // The request is inspected here next with Dry-Run support
    createProxyMiddleware({
        router: async (req) => {
            return (req as any).targetUrl || process.env.UPSTREAM_TARGET_URL;
        },
        changeOrigin: true,
        // Ensure the proxy forwards the original client IP to downstream targets
        xfwd: true,
        on: {
            proxyReq: (proxyReq, req, res) => {
                // Strip the Aegis API key before forwarding downstream
                proxyReq.removeHeader('x-aegis-api-key');
                fixRequestBody(proxyReq, req);
            },
            error: (err, req, res) => {
                if (res instanceof ServerResponse && !res.headersSent) {
                    res.writeHead(502, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Bad Gateway', message: 'Upstream service unreachable.' }));
                }
            }
        }
    })
);

app.use((req, res) => {
    res.status(404).json({ error: 'Not Found', message: 'Endpoint path configuration route missing.' });
});

app.listen(PORT, async () => {
    console.log(`=================================================`);
    console.log(`🛡️  AegisGate Core Proxy Server running on port: ${PORT}`);
    console.log(`🔐 Dynamic SaaS Multi-Tenant Routing & Edge Auth Engaged`);
    console.log(`=================================================`);

    // Establish persistent MongoDB connection
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