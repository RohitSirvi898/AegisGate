import crypto from 'node:crypto';
import type { Request, Response, NextFunction } from 'express';
import { ServerResponse } from 'node:http';
import { recordTelemetryEvent } from './telemetry.js';

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
    rule?: string;
    summary?: string;
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
 * Ensures 'X-Request-Id' response header is set and telemetry is captured.
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

        // Record pre-queue sanitized telemetry event for gateway rejection
        if (req) {
            try {
                recordTelemetryEvent({
                    requestId,
                    timestamp: new Date().toISOString(),
                    projectId: (req as any).projectId,
                    apiKeyId: (req as any).apiKeyId,
                    clientIp: (req as any).clientIp || req.socket?.remoteAddress || '127.0.0.1',
                    method: req.method || 'GET',
                    path: req.originalUrl || req.url || '/',
                    statusCode,
                    errorCode,
                    rule: options?.rule || (req as any).matchedRule,
                    summary: options?.summary,
                    headers: req.headers,
                    query: req.query,
                    rawBody: (req as any).rawBody || req.body
                });
            } catch {
                // Telemetry failure must never impede error response delivery
            }
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
