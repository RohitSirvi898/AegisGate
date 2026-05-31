import express, { type Request, type Response, type NextFunction } from 'express';
import { createProxyMiddleware, fixRequestBody, type Options } from 'http-proxy-middleware';
import dotenv from 'dotenv';
import { ServerResponse } from 'http';
import cors from 'cors';
import mongoose from 'mongoose';
import { rateLimiter } from './middleware/rateLimiter.js';
import { authenticateAndAuthorize } from './middleware/authenticate.js';
import { aiFirewall } from './middleware/aiFirewall.js';
import { initQueue, publishThreatLog } from './config/queue.js';
import { ThreatLogModel } from './models/threatLog.js';
import { ProjectModel } from './models/project.js';
import crypto from 'crypto';

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

// Native local Express route handler directly for the /api/v1/users endpoint
app.all('/api/v1/users', authenticateAndAuthorize(['admin', 'developer', 'user']), aiFirewall, (req, res) => {
    // 1. Process local user array data instantly
    const userData = { status: "success", data: [] };

    // 2. Fire background telemetry logic to FastAPI exactly as currently written
    const pathLength = (req.originalUrl || req.url || '').length;
    const methodLength = (req.method || '').length;
    const timestampFraction = (Date.now() % 10000) / 10000;
    const contentLength = Number(req.headers['content-length']) || 0;
    const telemetryPayload = {
        metrics: [
            pathLength / 100.0,
            methodLength / 10.0,
            timestampFraction,
            contentLength / 1000.0
        ]
    };
    fetch(AI_ANOMALY_ENGINE_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(telemetryPayload)
    }).catch((err) => {
        console.error('[Telemetry Fail-Open Bypass] Silently bypassed anomaly engine exception:', (err as Error).message);
    });
    // 3. Instantly return local payload to client
    return res.status(200).json(userData);
});

// GET /api/v1/analytics/telemetry route querying live threat logs from MongoDB
app.get('/api/v1/analytics/telemetry', async (req, res) => {
    try {
        const projectId = (req.headers['x-project-id'] as string) || 'aegis_default_project';

        const logs = await ThreatLogModel.find({ projectId })
            .sort({ createdAt: -1 })
            .limit(50);

        const totalBlocks = await ThreatLogModel.countDocuments({ projectId });
        const criticalCount = await ThreatLogModel.countDocuments({ projectId, severity: 'CRITICAL' });
        const highCount = await ThreatLogModel.countDocuments({ projectId, severity: 'HIGH' });

        return res.status(200).json({
            totalBlocks,
            criticalCount,
            highCount,
            logs
        });
    } catch (error: any) {
        console.error('❌ Failed to fetch telemetry statistics:', error.message);
        return res.status(500).json({
            error: 'Internal Server Error',
            message: 'Failed to retrieve real-time analytics telemetry data.'
        });
    }
});


// POST /api/v1/projects endpoint to register a new project and generate secure API keys
app.post('/api/v1/projects', async (req: Request, res: Response) => {
    try {
        const { projectName } = req.body;
        if (!projectName || typeof projectName !== 'string' || projectName.trim() === '') {
            return res.status(400).json({
                error: 'Bad Request',
                message: 'Project name is required and must be a valid non-empty string.'
            });
        }

        // Generate a secure random token prefixed with ag_live_ using crypto
        const apiKey = `ag_live_${crypto.randomBytes(24).toString('hex')}`;
        
        const newProject = new ProjectModel({
            projectName: projectName.trim(),
            developerId: 'default_developer', // Hardcoded developer ID for billing
            apiKey
        });

        await newProject.save();

        return res.status(201).json(newProject);
    } catch (error: any) {
        console.error('❌ Failed to provision project:', error.message);
        return res.status(500).json({
            error: 'Internal Server Error',
            message: 'Failed to provision a new project and secure API key.'
        });
    }
});

// POST /api/v1/analytics/telemetry endpoint to ingest developer threat logs asynchronously
app.post('/api/v1/analytics/telemetry', async (req: Request, res: Response) => {
    try {
        // Extract the custom Aegis API Key from headers
        const apiKeyHeader = req.headers['x-aegis-api-key'];
        if (!apiKeyHeader || typeof apiKeyHeader !== 'string') {
            return res.status(401).json({
                error: 'Unauthorized',
                message: 'Missing Aegis API Key header.'
            });
        }

        // Query Project collection using Mongoose Project model to validate the key
        const project = await ProjectModel.findOne({ apiKey: apiKeyHeader });
        if (!project) {
            return res.status(401).json({
                error: 'Unauthorized',
                message: 'Invalid or revoked Aegis API Key.'
            });
        }

        // Extract internal database project ID and stamp payload
        const projectId = String(project._id);

        const telemetryPayload = {
            projectId,
            clientIp: req.body.clientIp || req.ip || req.socket.remoteAddress || 'unknown-client',
            endpoint: req.body.endpoint || '',
            method: req.body.method || 'POST',
            timestamp: req.body.timestamp || new Date().toISOString(),
            rawBody: typeof req.body.rawBody === 'string' ? req.body.rawBody : JSON.stringify(req.body.rawBody || {})
        };

        // Forward enriched payload down system pipeline into RabbitMQ security bus
        await publishThreatLog(telemetryPayload);

        return res.status(202).json({
            success: true,
            message: 'Telemetry packet queued for asynchronous auditing.',
            projectId
        });
    } catch (error: any) {
        console.error('❌ Failed to ingest analytics telemetry:', error.message);
        return res.status(500).json({
            error: 'Internal Server Error',
            message: 'Failed to ingest telemetry payload.'
        });
    }
});

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

app.use((req, res) => {
    res.status(404).json({ error: 'Not Found', message: 'Endpoint path configuration route missing.' });
});

app.listen(PORT, async () => {
    console.log(`=================================================`);
    console.log(`🛡️  AegisGate Core Proxy Server running on port: ${PORT}`);
    console.log(`🔐 Edge Auth Protection & RBAC Layers Engaged`);
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