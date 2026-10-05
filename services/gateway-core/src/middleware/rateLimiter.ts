import type { Request, Response, NextFunction } from 'express';
import { redisClient } from '../config/redis.js';
import { getClientIp } from '../utils/ip.js';
import { sendGatewayError } from '../utils/errors.js';

const WINDOW_SIZE_IN_SECONDS = 60;
const MAX_REQUEST_LIMIT = 20; // Allow 20 requests per minute per IP

export const rateLimiter = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    // Exempt control plane and admin polling from public ingress rate limiting
    if (
        req.path.startsWith('/api/v1/admin') ||
        req.path.startsWith('/api/v1/analytics') ||
        req.originalUrl?.startsWith('/api/v1/admin') ||
        req.originalUrl?.startsWith('/api/v1/analytics')
    ) {
        return next();
    }

    const clientIp = (req as any).clientIp || getClientIp(req);
    (req as any).clientIp = clientIp;

    const currentWindow = Math.floor(Date.now() / (WINDOW_SIZE_IN_SECONDS * 1000));
    const redisKey = `rate_limit:${clientIp}:${currentWindow}`;

    try {
        // Atomic Redis INCR + EXPIRE rate limiting command
        const result = await redisClient.rateLimitIncr(
            redisKey,
            WINDOW_SIZE_IN_SECONDS,
            MAX_REQUEST_LIMIT
        );

        if (result === 1) {
            // Request is allowed. Call next()
            next();
        } else {
            // Request is blocked. Immediately return status 429 with standard error payload and Retry-After header
            sendGatewayError(res, 429, 'rate_limited', req, {
                retryAfterSeconds: WINDOW_SIZE_IN_SECONDS
            });
        }
    } catch (error: any) {
        console.error(`[Rate Limiter Fault Check] Degrading rate limiter layer gracefully:`, error?.message || error);
        // Fail-Open Resiliency: If Redis is unreachable, attach X-Aegis-Limiter-Degraded header and allow request to proceed
        res.setHeader('X-Aegis-Limiter-Degraded', 'true');
        next();
    }
};