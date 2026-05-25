import type { Request, Response, NextFunction } from 'express';
import { redisClient } from '../config/redis.js';

const WINDOW_SIZE_IN_SECONDS = 60;
const MAX_REQUEST_LIMIT = 100; // Allow 100 requests per minute per IP

export const rateLimiter = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    // Gracefully fallback to standard loopback IP if header is missing
    const clientIp = req.ip || req.socket.remoteAddress || 'unknown-client';
    const redisKey = `rate_limit:${clientIp}`;

    const now = Date.now();
    const windowStart = now - (WINDOW_SIZE_IN_SECONDS * 1000);

    try {
        // Call the custom script awaitable command
        const result = await redisClient.slidingWindowRateLimit(
            redisKey,
            now,
            windowStart,
            MAX_REQUEST_LIMIT,
            WINDOW_SIZE_IN_SECONDS
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
    } catch (error) {
        console.error(`[Rate Limiter Fault Check] Degrading protection layer gracefully:`, error);
        // Fault Resilience: Fail-Open Policy to let traffic pass through if Redis cluster drops
        next();
    }
};