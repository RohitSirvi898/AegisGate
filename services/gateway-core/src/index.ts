import express from 'express';
import { createProxyMiddleware, type Options } from 'http-proxy-middleware';
import dotenv from 'dotenv';
import { ServerResponse } from 'http';
import { rateLimiter } from './middleware/rateLimiter.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 8080;

// Apply the global sliding-window rate limiter directly across all incoming request hooks
app.use(rateLimiter);

const routingTable: Record<string, string> = {
    '/api/v1/users': 'http://httpbin.org/anything/users',
    '/api/v1/payments': 'http://httpbin.org/anything/payments'
};

Object.entries(routingTable).forEach(([path, target]) => {
    const proxyOptions: Options = {
        target,
        changeOrigin: true,
        pathRewrite: { [`^${path}`]: '' },
        on: {
            error: (err, req, res) => {
                if (res instanceof ServerResponse && !res.headersSent) {
                    res.writeHead(502, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({
                        error: 'Bad Gateway',
                        message: 'The upstream backend service is currently unreachable.',
                        timestamp: new Date().toISOString()
                    }));
                }
            }
        }
    };
    app.use(path, createProxyMiddleware(proxyOptions));
});

app.listen(PORT, () => {
    console.log(`=================================================`);
    console.log(`🛡️  AegisGate Core Proxy Server running on port: ${PORT}`);
    console.log(`=================================================`);
});