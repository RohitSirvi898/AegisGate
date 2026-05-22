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
        // 1. Initiate an Atomic Transaction Pipeline
        const pipeline = redisClient.multi();

        // Remove elements older than our sliding window threshold
        pipeline.zremrangebyscore(redisKey, 0, windowStart);
        // Retrieve the total remaining request tokens in this user's current window
        pipeline.zcard(redisKey);
        // Inject the current hit timestamp into the client's sorted collection set
        pipeline.zadd(redisKey, now, now.toString());
        // Automatically expire the tracking collection set key after window size to conserve RAM memory leaks
        pipeline.expire(redisKey, WINDOW_SIZE_IN_SECONDS);

        // Execute the atomic cluster batch pipeline execution
        const results = await pipeline.exec();

        if (!results) {
            throw new Error('Redis transaction execution returned null state');
        }

        // Extraction parsing mapping logic: results[1] holds the ZCARD response array: [error, result]
        const zcardResult = results[1];
        if (!zcardResult) {
            throw new Error('Redis transaction did not return ZCARD result');
        }

        const [zcardError, zcardCount] = zcardResult;
        if (zcardError) {
            throw zcardError;
        }

        const requestCount = zcardCount as number;

        // 2. Evaluate if threshold boundaries have been broken
        if (requestCount >= MAX_REQUEST_LIMIT) {
            res.status(429).json({
                error: 'Too Many Requests',
                message: `API consumption threshold exceeded. Maximum allows ${MAX_REQUEST_LIMIT} requests per minute. Please try again later.`,
                retryAfterSeconds: Math.ceil((windowStart + (WINDOW_SIZE_IN_SECONDS * 1000) - now) / 1000),
                timestamp: new Date().toISOString()
            });
            return;
        }

        // Standard non-blocking instrumentation trace response tracking headers
        res.setHeader('X-RateLimit-Limit', MAX_REQUEST_LIMIT);
        res.setHeader('X-RateLimit-Remaining', Math.max(0, MAX_REQUEST_LIMIT - requestCount - 1));

        next();
    } catch (error) {
        console.error(`[Rate Limiter Fault Check] Degrading protection layer gracefully:`, error);
        // Fault Resilience: In a professional startup system, if your cache tier drops, you don't break your customer's experience.
        // We log the trace failure but proceed execution context onward.
        next();
    }
};