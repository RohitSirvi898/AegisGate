import { Router } from 'express';
import { authenticateAndAuthorize } from '../middleware/authenticate.js';
import { aiFirewall } from '../middleware/aiFirewall.js';

const usersRouter = Router();
const AI_ANOMALY_ENGINE_URL = process.env.AI_ANOMALY_ENGINE_URL || 'http://localhost:8000/analyze';

/**
 * ALL /
 * Handler directly for the /api/v1/users endpoint.
 */
usersRouter.all('/', authenticateAndAuthorize(['admin', 'developer', 'user']), aiFirewall, (req, res) => {
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

export { usersRouter };
