import type { Request, Response, NextFunction } from 'express';
import { redisClient } from '../config/redis.js';

export interface RouteCacheConfig {
    enabled: boolean;
    ttlSec?: number;
    allowedQueryParams?: string[];
}

export interface CachedResponse {
    body: string;
    contentType: string;
    statusCode: number;
    headers?: Record<string, string>;
}

// PRD v2.1 Configuration Defaults
export const CACHE_TTL_SEC = Number(process.env.CACHE_TTL_SEC) || 60;
export const CACHE_MAX_BODY_BYTES = Number(process.env.CACHE_MAX_BODY_BYTES) || 262144; // 256KB
export const CACHE_MAX_KEY_BYTES = Number(process.env.CACHE_MAX_KEY_BYTES) || 512;

// In-memory single-flight promise map per cache key to prevent cache stampedes (dog-piling)
const inFlightFetches = new Map<string, Promise<CachedResponse | null>>();

/**
 * Normalizes URL path according to PRD v2.1 Section 4.7:
 * - Decodes unreserved percent-escapes.
 * - Collapses duplicate slashes.
 * - Removes dot segments (. and ..).
 * - Bypasses cache if path contains encoded slashes (%2f / %2F).
 */
export function normalizePath(rawPath: string): string | null {
    if (/%2f/i.test(rawPath)) {
        return null;
    }

    let decoded: string;
    try {
        decoded = decodeURI(rawPath);
    } catch {
        return null;
    }

    // Collapse multiple consecutive slashes
    let normalized = decoded.replace(/\/+/g, '/');

    // Remove dot segments
    const segments = normalized.split('/');
    const cleanSegments: string[] = [];
    for (const seg of segments) {
        if (seg === '.' || seg === '') {
            continue;
        } else if (seg === '..') {
            cleanSegments.pop();
        } else {
            cleanSegments.push(seg);
        }
    }

    return '/' + cleanSegments.join('/');
}

/**
 * Builds the canonical Redis cache key format:
 * `cache:{projectId}:{routeId}:GET:{normalizedPath}?{sortedAllowedQuery}`
 * Returns null if key length exceeds CACHE_MAX_KEY_BYTES (512).
 */
export function buildCacheKey(
    projectId: string,
    routeId: string,
    normalizedPath: string,
    query: Record<string, any>,
    allowedQueryParams: string[]
): string | null {
    const allowedSet = new Set(allowedQueryParams);

    // Only include parameters that are present in both the request and the allowed list
    const matchingKeys = Object.keys(query)
        .filter(key => allowedSet.has(key))
        .sort();

    const queryParts: string[] = [];
    for (const key of matchingKeys) {
        const val = query[key];
        if (Array.isArray(val)) {
            const sortedArray = [...val].map(String).sort();
            for (const item of sortedArray) {
                queryParts.push(`${encodeURIComponent(key)}=${encodeURIComponent(item)}`);
            }
        } else if (val !== undefined && val !== null) {
            queryParts.push(`${encodeURIComponent(key)}=${encodeURIComponent(String(val))}`);
        }
    }

    const queryStr = queryParts.join('&');
    const cacheKey = `cache:${projectId}:${routeId}:GET:${normalizedPath}${queryStr ? '?' + queryStr : ''}`;

    if (Buffer.byteLength(cacheKey, 'utf8') > CACHE_MAX_KEY_BYTES) {
        return null;
    }

    return cacheKey;
}

/**
 * Calculates TTL with ±10% jitter (e.g. 60s -> 54s..66s) to avoid synchronized expiry stampedes.
 */
export function calculateJitteredTtl(baseTtl: number): number {
    const jitterFraction = (Math.random() * 0.2) - 0.1; // -0.10 to +0.10
    const jittered = Math.round(baseTtl * (1 + jitterFraction));
    return Math.max(1, jittered);
}

/**
 * Safe Response Caching Middleware conforming to PRD v2.1 Section 4.7.
 */
export function createResponseCacheMiddleware(routeResolver?: (req: Request) => RouteCacheConfig | undefined) {
    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        // Rule 1: Method must be GET
        if (req.method !== 'GET') {
            return next();
        }

        // Determine route cache configuration
        const routeConfig: RouteCacheConfig | undefined =
            routeResolver?.(req) ||
            (req as any).routeConfig?.cache ||
            (req as any).routeCache;

        // If caching is not enabled for this route, proceed without setting cache headers
        if (!routeConfig || !routeConfig.enabled) {
            return next();
        }

        // Rule 2: Strict BYPASS if request contains Authorization or Cookie headers
        if (req.headers.authorization || req.headers.cookie) {
            res.setHeader('X-Aegis-Cache', 'BYPASS');
            return next();
        }

        // Rule 3: Query Parameter Check
        // All query params in the request MUST exist in route.allowedQueryParams
        const allowedQueryParams = routeConfig.allowedQueryParams || [];
        const allowedSet = new Set(allowedQueryParams);
        const reqQueryKeys = Object.keys(req.query);

        const hasUnallowedParam = reqQueryKeys.some(key => !allowedSet.has(key));
        if (hasUnallowedParam) {
            res.setHeader('X-Aegis-Cache', 'BYPASS');
            return next();
        }

        // Rule 4: Path normalization and encoded slash check
        const normalizedPath = normalizePath(req.path);
        if (!normalizedPath) {
            res.setHeader('X-Aegis-Cache', 'BYPASS');
            return next();
        }

        // Rule 5: Build cache key
        const projectId = (req as any).projectId || 'default_project';
        const routeId = (req as any).routeId || req.baseUrl || normalizedPath;
        const cacheKey = buildCacheKey(projectId, routeId, normalizedPath, req.query, allowedQueryParams);

        if (!cacheKey) {
            res.setHeader('X-Aegis-Cache', 'BYPASS');
            return next();
        }

        // Check Redis cache (Cache Hit Path)
        try {
            const cachedRaw = await redisClient.get(cacheKey);
            if (cachedRaw) {
                try {
                    const cached: CachedResponse = JSON.parse(cachedRaw);
                    res.setHeader('X-Aegis-Cache', 'HIT');
                    if (cached.contentType) {
                        res.setHeader('Content-Type', cached.contentType);
                    }
                    res.status(cached.statusCode || 200).send(cached.body);
                    return;
                } catch {
                    // Malformed cache entry, ignore and fall through
                }
            }
        } catch (redisErr: any) {
            console.warn('[Cache Redis Read Error - Fail Open]:', redisErr?.message || redisErr);
            res.setHeader('X-Aegis-Cache', 'BYPASS');
            return next();
        }

        // Single-Flight Stampede Protection:
        // If another request is currently fetching this exact key, await its outcome
        const existingFlight = inFlightFetches.get(cacheKey);
        if (existingFlight) {
            try {
                const coalesced = await existingFlight;
                if (coalesced) {
                    res.setHeader('X-Aegis-Cache', 'HIT');
                    if (coalesced.contentType) {
                        res.setHeader('Content-Type', coalesced.contentType);
                    }
                    res.status(coalesced.statusCode || 200).send(coalesced.body);
                    return;
                }
            } catch {
                // Upstream failed for coalesced request, continue to independent proxy
            }
        }

        // Set response header for cache miss
        res.setHeader('X-Aegis-Cache', 'MISS');

        // Create deferred promise for single-flight coalescing
        let resolveFlight: (val: CachedResponse | null) => void = () => {};
        const flightPromise = new Promise<CachedResponse | null>((resolve) => {
            resolveFlight = resolve;
        });
        inFlightFetches.set(cacheKey, flightPromise);

        // Intercept upstream response chunks before proxy transmits them to client
        const originalWrite = res.write.bind(res);
        const originalEnd = res.end.bind(res);
        const chunks: Buffer[] = [];
        let totalBytes = 0;
        let bodyTooLarge = false;

        res.write = function (chunk: any, ...args: any[]): boolean {
            if (chunk) {
                const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
                totalBytes += buf.length;
                if (totalBytes <= CACHE_MAX_BODY_BYTES) {
                    chunks.push(buf);
                } else {
                    bodyTooLarge = true;
                }
            }
            return (originalWrite as any)(chunk, ...args);
        } as any;

        res.end = function (chunk?: any, ...args: any[]): Response {
            if (chunk) {
                const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
                totalBytes += buf.length;
                if (totalBytes <= CACHE_MAX_BODY_BYTES) {
                    chunks.push(buf);
                } else {
                    bodyTooLarge = true;
                }
            }

            // Inspect response headers and eligibility before storing
            const statusCode = res.statusCode;
            const setCookie = res.getHeader('set-cookie');
            const cacheControl = String(res.getHeader('cache-control') || '').toLowerCase();
            const vary = String(res.getHeader('vary') || '').toLowerCase();
            const contentType = String(res.getHeader('content-type') || 'application/json');

            const is200 = statusCode === 200;
            const hasNoSetCookie = !setCookie;
            const notNoStore = !cacheControl.includes('no-store') && !cacheControl.includes('private');
            const validVary = !vary || vary === 'accept-encoding';
            const eligibleForStorage = is200 && hasNoSetCookie && notNoStore && validVary && !bodyTooLarge;

            if (eligibleForStorage) {
                const bodyStr = Buffer.concat(chunks).toString('utf8');
                const cachedPayload: CachedResponse = {
                    body: bodyStr,
                    contentType,
                    statusCode
                };

                const ttl = calculateJitteredTtl(routeConfig.ttlSec || CACHE_TTL_SEC);

                redisClient.setex(cacheKey, ttl, JSON.stringify(cachedPayload)).catch((err) => {
                    console.warn('[Cache Redis Write Error - Fail Open]:', err?.message || err);
                });

                resolveFlight(cachedPayload);
            } else {
                resolveFlight(null);
            }

            inFlightFetches.delete(cacheKey);
            return (originalEnd as any)(chunk, ...args);
        } as any;

        next();
    };
}
