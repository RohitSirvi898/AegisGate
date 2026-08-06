import type { Request, Response, NextFunction } from 'express';
import { redisClient } from '../config/redis.js';

const WINDOW_SIZE_IN_SECONDS = 60;
const MAX_REQUEST_LIMIT = 100; // Allow 100 requests per minute per IP

export const rateLimiter = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    // Gracefully fallback to standard loopback IP if header is missing
    const clientIp = req.ip || req.socket.remoteAddress || 'unknown-client';
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
            // Request is blocked. Immediately return status 429 with JSON error payload and set a 'Retry-After' header
            res.setHeader('Retry-After', WINDOW_SIZE_IN_SECONDS.toString());
            res.status(429).json({
                error: 'Too Many Requests',
                message: `API consumption threshold exceeded. Maximum allows ${MAX_REQUEST_LIMIT} requests per minute. Please try again later.`,
                retryAfterSeconds: WINDOW_SIZE_IN_SECONDS,
                timestamp: new Date().toISOString()
            });
        }
    } catch (error: any) {
        console.error(`[Rate Limiter Fault Check] Degrading rate limiter layer gracefully:`, error?.message || error);
        // Fail-Open Resiliency: If Redis is unreachable, attach X-Aegis-Limiter-Degraded header and allow request to proceed
        res.setHeader('X-Aegis-Limiter-Degraded', 'true');
        next();
    }
};