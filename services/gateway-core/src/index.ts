import express from 'express';
import { createProxyMiddleware, type Options } from 'http-proxy-middleware';
import dotenv from 'dotenv';
import { ServerResponse } from 'http';
import { rateLimiter } from './middleware/rateLimiter.js';
import { authenticateAndAuthorize } from './middleware/authenticate.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 8080;

// Apply global DDoS firewall log rate metrics across all entries
app.use(rateLimiter);

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
    // Temporarily stub/intercept the /api/v1/users route to bypass Gunicorn downstream and isolate gateway/rate-limiter benchmarking
    if (path === '/api/v1/users') {
        app.use(path, authenticateAndAuthorize(roles), (req, res) => {
            res.status(200).json({ status: "success", message: "Static Gateway Benchmark Bypass" });
        });
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
            }
        }
    };

    // Secure path execution wrapper: [Rate Limit] -> [JWT/RBAC Check] -> [Proxy Stream Forwarding]
    app.use(path, authenticateAndAuthorize(roles), createProxyMiddleware(proxyOptions));
});

app.use((req, res) => {
    res.status(404).json({ error: 'Not Found', message: 'Endpoint path configuration route missing.' });
});

app.listen(PORT, () => {
    console.log(`=================================================`);
    console.log(`🛡️  AegisGate Core Proxy Server running on port: ${PORT}`);
    console.log(`🔐 Edge Auth Protection & RBAC Layers Engaged`);
    console.log(`=================================================`);
});