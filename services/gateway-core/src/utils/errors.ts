import crypto from 'node:crypto';
import type { Request, Response, NextFunction } from 'express';
import { ServerResponse } from 'node:http';

export type GatewayErrorCode =
    | 'invalid_or_missing_credentials'
    | 'ip_jailed'
    | 'request_blocked'
    | 'payload_too_large'
    | 'rate_limited'
    | 'upstream_unavailable'
    | 'upstream_saturated'
    | 'auth_backend_unavailable'
    | 'upstream_timeout';

export interface GatewayErrorResponse {
    error: GatewayErrorCode;
    requestId: string;
}

export interface SendGatewayErrorOptions {
    retryAfterSeconds?: number;
    headers?: Record<string, string>;
}

export const DEFAULT_STATUS_CODES: Record<GatewayErrorCode, number> = {
    invalid_or_missing_credentials: 401,
    ip_jailed: 403,
    request_blocked: 403,
    payload_too_large: 413,
    rate_limited: 429,
    upstream_unavailable: 503,
    upstream_saturated: 503,
    auth_backend_unavailable: 503,
    upstream_timeout: 504
};

/**
 * Extracts or generates an X-Request-Id for the request,
 * attaches it to the request context and sets the response header.
 */
export function getOrSetRequestId(req?: Request, res?: Response | ServerResponse): string {
    let requestId: string | undefined;

    if (req) {
        if ((req as any).requestId && typeof (req as any).requestId === 'string') {
            requestId = (req as any).requestId;
        } else {
            const rawHeader = req.headers['x-request-id'];
            if (typeof rawHeader === 'string' && rawHeader.trim().length > 0) {
                requestId = rawHeader.trim();
            } else if (Array.isArray(rawHeader) && rawHeader[0] && rawHeader[0].trim().length > 0) {
                requestId = rawHeader[0].trim();
            }
        }
    }

    if (!requestId && res && !res.headersSent) {
        const existingResHeader = res.getHeader('x-request-id');
        if (typeof existingResHeader === 'string' && existingResHeader.trim().length > 0) {
            requestId = existingResHeader.trim();
        }
    }

    if (!requestId) {
        requestId = crypto.randomUUID();
    }

    if (req) {
        (req as any).requestId = requestId;
    }

    if (res && !res.headersSent) {
        res.setHeader('X-Request-Id', requestId);
    }

    return requestId;
}

/**
 * Sends a standard gateway error JSON payload conforming to PRD v2.1:
 * { "error": "<code>", "requestId": "<id>" }
 * Ensures 'X-Request-Id' response header is set.
 */
export function sendGatewayError(
    res: Response | ServerResponse,
    statusCode: number,
    errorCode: GatewayErrorCode,
    req?: Request,
    options?: SendGatewayErrorOptions
): void {
    const requestId = getOrSetRequestId(req, res);

    if (!res.headersSent) {
        res.setHeader('X-Request-Id', requestId);

        if (errorCode === 'rate_limited' && options?.retryAfterSeconds !== undefined) {
            res.setHeader('Retry-After', options.retryAfterSeconds.toString());
        }

        if (options?.headers) {
            for (const [key, val] of Object.entries(options.headers)) {
                res.setHeader(key, val);
            }
        }

        const payload: GatewayErrorResponse = {
            error: errorCode,
            requestId
        };

        if ('status' in res && typeof res.status === 'function') {
            // Express Response
            (res as Response).status(statusCode).json(payload);
        } else {
            // Raw Node.js ServerResponse
            res.writeHead(statusCode, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(payload));
        }
    }
}

/**
 * Express middleware to guarantee X-Request-Id assignment at ingress.
 */
export const requestIdMiddleware = (req: Request, res: Response, next: NextFunction): void => {
    getOrSetRequestId(req, res);
    next();
};
