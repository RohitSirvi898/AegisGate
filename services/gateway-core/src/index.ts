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
import { ThreatLogModel } from './models/threatLog.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 8080;

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
    fetch('http://localhost:8000/analyze', {
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
    fetch('http://localhost:8000/analyze', {
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
        const logs = await ThreatLogModel.find()
            .sort({ createdAt: -1 })
            .limit(50);

        const totalBlocks = await ThreatLogModel.countDocuments();
        const criticalCount = await ThreatLogModel.countDocuments({ severity: 'CRITICAL' });
        const highCount = await ThreatLogModel.countDocuments({ severity: 'HIGH' });

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