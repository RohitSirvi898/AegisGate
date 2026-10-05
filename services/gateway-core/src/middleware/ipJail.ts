import type { Request, Response, NextFunction } from 'express';
import { redisClient } from '../config/redis.js';
import { getClientIp, normalizeClientIp } from '../utils/ip.js';
import { sendGatewayError } from '../utils/errors.js';

const ABUSE_THRESHOLD = Number(process.env.ABUSE_THRESHOLD) || 3;
const ABUSE_WINDOW_SECONDS = Number(process.env.ABUSE_WINDOW_SECONDS) || 60;
const JAIL_TTL_SECONDS = Number(process.env.JAIL_TTL_SECONDS) || 600;

const RECORD_ABUSE_LUA = `
local abuseKey = KEYS[1]
local jailKey = KEYS[2]
local points = tonumber(ARGV[1]) or 1
local threshold = tonumber(ARGV[2]) or 3
local abuseTtl = tonumber(ARGV[3]) or 60
local jailTtl = tonumber(ARGV[4]) or 600

local current = redis.call("INCRBY", abuseKey, points)
local ttl = redis.call("TTL", abuseKey)
if ttl == -1 then
    redis.call("EXPIRE", abuseKey, abuseTtl)
end

if current >= threshold then
    redis.call("SETEX", jailKey, jailTtl, "banned")
    return { current, 1 }
else
    return { current, 0 }
end
`;

/**
 * Atomic helper to record abuse points against a client IP in Redis.
 * If abuse score reaches threshold (default: 3 points within 60s),
 * sets jail:{clientIp} = "banned" with TTL = 600s (10 minutes).
 */
export async function recordAbuseEvent(
    clientIp: string,
    points: number = 1
): Promise<{ score: number; jailed: boolean }> {
    const cleanIp = normalizeClientIp(clientIp);

    try {
        const result = (await redisClient.eval(
            RECORD_ABUSE_LUA,
            2,
            `abuse:${cleanIp}`,
            `jail:${cleanIp}`,
            points.toString(),
            ABUSE_THRESHOLD.toString(),
            ABUSE_WINDOW_SECONDS.toString(),
            JAIL_TTL_SECONDS.toString()
        )) as any;

        if (Array.isArray(result)) {
            const score = Number(result[0]) || 0;
            const jailed = Number(result[1]) === 1;
            return { score, jailed };
        }

        return { score: 0, jailed: false };
    } catch (err: any) {
        console.error(`[Record Abuse Error for IP ${cleanIp}]:`, err?.message || err);
        return { score: 0, jailed: false };
    }
}

/**
 * Checks whether an IP is currently banned in the Redis jail.
 */
export async function isIpJailed(clientIp: string): Promise<boolean> {
    try {
        const cleanIp = normalizeClientIp(clientIp);
        const exists = await redisClient.exists(`jail:${cleanIp}`);
        return exists === 1;
    } catch (err: any) {
        console.error(`[IP Jail Check Error for ${clientIp}]:`, err?.message || err);
        return false;
    }
}

/**
 * Admin helper to unban an IP address by deleting both jail and abuse keys.
 */
export async function unbanIp(clientIp: string): Promise<boolean> {
    try {
        const cleanIp = normalizeClientIp(clientIp);
        const deleted = await redisClient.del(`jail:${cleanIp}`, `abuse:${cleanIp}`);
        return deleted > 0;
    } catch (err: any) {
        console.error(`[Admin Unban IP Error for ${clientIp}]:`, err?.message || err);
        return false;
    }
}

/**
 * Admin helper to retrieve all currently banned client IPs and their remaining TTLs.
 */
export async function getJailedIps(): Promise<Array<{ ip: string; ttl: number }>> {
    try {
        const keys = await redisClient.keys('jail:*');
        const jailedList: Array<{ ip: string; ttl: number }> = [];
        for (const key of keys) {
            const ip = key.replace(/^jail:/, '');
            const ttl = await redisClient.ttl(key);
            jailedList.push({ ip, ttl: ttl > 0 ? ttl : 0 });
        }
        return jailedList;
    } catch (err: any) {
        console.error('[Get Jailed IPs Error]:', err?.message || err);
        return [];
    }
}

/**
 * Step 3 in pipeline: Fast Redis IP-Jail Check.
 * If jail:{clientIp} exists, immediately short-circuit with HTTP 403:
 * { "error": "ip_jailed", "requestId": "<id>" }
 */
export const ipJailMiddleware = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    // Exempt control plane and admin routes so admin operations remain accessible
    if (
        req.path.startsWith('/api/v1/admin') ||
        req.path.startsWith('/api/v1/analytics') ||
        req.originalUrl?.startsWith('/api/v1/admin') ||
        req.originalUrl?.startsWith('/api/v1/analytics')
    ) {
        return next();
    }

    try {
        const clientIp = (req as any).clientIp || getClientIp(req);
        (req as any).clientIp = clientIp;

        const banned = await isIpJailed(clientIp);
        if (banned) {
            sendGatewayError(res, 403, 'ip_jailed', req);
            return;
        }

        next();
    } catch (err: any) {
        console.error('[IP Jail Fast-Check Error - Fail Open]:', err?.message || err);
        // Fail-Open Resiliency: Redis fault should not block legitimate ingress traffic
        res.setHeader('X-Aegis-Jail-Degraded', 'true');
        next();
    }
};
