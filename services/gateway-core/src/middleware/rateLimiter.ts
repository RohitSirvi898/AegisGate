import type { NextFunction, Request, Response } from 'express';

import { redisClient } from '../config/redis.js';
import { sendGatewayError } from '../utils/errors.js';
import { getClientIp } from '../utils/ip.js';

const WINDOW_SIZE_IN_SECONDS = 60;
const MAX_REQUEST_LIMIT = 20;

export const rateLimiter = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
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
    const result = await redisClient.rateLimitIncr(
      redisKey,
      WINDOW_SIZE_IN_SECONDS,
      MAX_REQUEST_LIMIT
    );

    if (result === 1) {
      next();
    } else {
      sendGatewayError(res, 429, 'rate_limited', req, {
        retryAfterSeconds: WINDOW_SIZE_IN_SECONDS
      });
    }
  } catch (error: any) {
    console.error(`[Rate Limiter Fault Check] Degrading rate limiter layer gracefully:`, error?.message || error);
    res.setHeader('X-Aegis-Limiter-Degraded', 'true');
    next();
  }
};