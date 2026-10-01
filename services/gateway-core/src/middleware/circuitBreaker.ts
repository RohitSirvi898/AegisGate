import http from 'node:http';
import https from 'node:https';
import type { Request, Response, NextFunction } from 'express';
import { ServerResponse } from 'node:http';
import { sendGatewayError } from '../utils/errors.js';
import { getSsrfSafeAgent } from '../utils/ssrf.js';

export type CircuitState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';

export interface UpstreamCircuitBreaker {
    origin: string;
    state: CircuitState;
    consecutiveFailures: number;
    lastStateChange: number;
    inFlight: number;
    probeInFlight: boolean;
}

// PRD v2.1 Configuration Defaults
export const BREAKER_FAILURE_THRESHOLD = Number(process.env.BREAKER_FAILURE_THRESHOLD) || 5;
export const BREAKER_COOLDOWN_MS = Number(process.env.BREAKER_COOLDOWN_MS) || 30000; // 30s
export const UPSTREAM_TIMEOUT_MS = Number(process.env.UPSTREAM_TIMEOUT_MS) || 5000;   // 5s
export const UPSTREAM_CONNECT_TIMEOUT_MS = Number(process.env.UPSTREAM_CONNECT_TIMEOUT_MS) || 2000; // 2s
export const MAX_INFLIGHT_PER_UPSTREAM = Number(process.env.MAX_INFLIGHT_PER_UPSTREAM) || 100;

// In-memory per-upstream origin circuit breaker registry
const circuitBreakers = new Map<string, UpstreamCircuitBreaker>();

/**
 * Extracts origin strictly as `${parsedUrl.protocol}//${parsedUrl.host}`
 */
export function extractOrigin(targetUrl: string): string | null {
    try {
        const parsed = new URL(targetUrl);
        return `${parsed.protocol}//${parsed.host}`;
    } catch {
        return null;
    }
}

/**
 * Retrieves or registers an in-memory circuit breaker state machine for an upstream origin.
 */
export function getOrCreateCircuitBreaker(origin: string): UpstreamCircuitBreaker {
    let breaker = circuitBreakers.get(origin);
    if (!breaker) {
        breaker = {
            origin,
            state: 'CLOSED',
            consecutiveFailures: 0,
            lastStateChange: Date.now(),
            inFlight: 0,
            probeInFlight: false
        };
        circuitBreakers.set(origin, breaker);
    }
    return breaker;
}

/**
 * Records a successful upstream communication (< 500 status code).
 * Resets consecutive failure counter and returns circuit to CLOSED.
 */
export function recordUpstreamSuccess(origin: string): void {
    const breaker = getOrCreateCircuitBreaker(origin);
    breaker.consecutiveFailures = 0;
    if (breaker.state !== 'CLOSED') {
        breaker.state = 'CLOSED';
        breaker.lastStateChange = Date.now();
    }
}

/**
 * Records an upstream failure (>= 500 status, timeout, or network connection drop).
 * Transitions state to OPEN if failures reach BREAKER_FAILURE_THRESHOLD.
 */
export function recordUpstreamFailure(origin: string): void {
    const breaker = getOrCreateCircuitBreaker(origin);
    breaker.consecutiveFailures++;

    if (breaker.state !== 'OPEN' && breaker.consecutiveFailures >= BREAKER_FAILURE_THRESHOLD) {
        breaker.state = 'OPEN';
        breaker.lastStateChange = Date.now();
        console.warn(`⚠️ [Circuit Breaker] Trip to OPEN for origin '${origin}' (${breaker.consecutiveFailures} consecutive failures)`);
    }
}

/**
 * Dispatches an asynchronous synthetic health probe during HALF_OPEN state.
 * Only ONE synthetic health probe is allowed through while probeInFlight is true.
 */
export function launchSyntheticHealthProbe(origin: string, healthCheckPath?: string): void {
    const breaker = getOrCreateCircuitBreaker(origin);
    const probePath = healthCheckPath && healthCheckPath.startsWith('/') ? healthCheckPath : '/';
    const probeUrl = `${origin}${probePath}`;

    const isHttps = origin.startsWith('https:');
    const requestModule = isHttps ? https : http;
    const agent = getSsrfSafeAgent(origin);

    try {
        const parsed = new URL(probeUrl);
        const req = requestModule.request(
            {
                protocol: parsed.protocol,
                hostname: parsed.hostname,
                port: parsed.port || (isHttps ? 443 : 80),
                path: parsed.pathname + parsed.search,
                method: 'GET',
                agent,
                timeout: UPSTREAM_TIMEOUT_MS,
                headers: {
                    'User-Agent': 'AegisGate-HealthProbe/2.1',
                    'Accept': '*/*'
                }
            },
            (res) => {
                // Consume response data to free socket
                res.resume();

                const statusCode = res.statusCode || 500;
                if (statusCode < 500) {
                    // Probe succeeded: Reset breaker to CLOSED
                    breaker.state = 'CLOSED';
                    breaker.consecutiveFailures = 0;
                    breaker.probeInFlight = false;
                    breaker.lastStateChange = Date.now();
                    console.log(`✅ [Circuit Breaker] Probe succeeded (${statusCode}) for origin '${origin}'. Circuit is now CLOSED.`);
                } else {
                    // Probe returned 5xx: Re-trip to OPEN for another cooldown cycle
                    breaker.state = 'OPEN';
                    breaker.lastStateChange = Date.now();
                    breaker.probeInFlight = false;
                    console.warn(`❌ [Circuit Breaker] Probe returned ${statusCode} for origin '${origin}'. Circuit remains OPEN.`);
                }
            }
        );

        req.on('timeout', () => {
            req.destroy(new Error('Synthetic health probe timed out'));
        });

        req.on('error', (err) => {
            breaker.state = 'OPEN';
            breaker.lastStateChange = Date.now();
            breaker.probeInFlight = false;
            console.warn(`❌ [Circuit Breaker] Probe failed for origin '${origin}': ${err.message}. Circuit remains OPEN.`);
        });

        req.end();
    } catch (err: any) {
        breaker.state = 'OPEN';
        breaker.lastStateChange = Date.now();
        breaker.probeInFlight = false;
        console.warn(`❌ [Circuit Breaker] Probe initialization failure for origin '${origin}':`, err?.message || err);
    }
}

/**
 * Evaluates the circuit breaker and bulkhead rules for an upstream origin.
 * Returns { allowed: true } or { allowed: false, reason: 'upstream_saturated' | 'upstream_unavailable' }.
 */
export function checkCircuitAndBulkhead(
    origin: string,
    healthCheckPath?: string
): { allowed: true } | { allowed: false; reason: 'upstream_saturated' | 'upstream_unavailable' } {
    const breaker = getOrCreateCircuitBreaker(origin);

    // 1. Bulkhead check: Reject if in-flight requests >= MAX_INFLIGHT_PER_UPSTREAM
    if (breaker.inFlight >= MAX_INFLIGHT_PER_UPSTREAM) {
        return { allowed: false, reason: 'upstream_saturated' };
    }

    const now = Date.now();

    // 2. State Machine Evaluation
    if (breaker.state === 'OPEN') {
        if (now - breaker.lastStateChange >= BREAKER_COOLDOWN_MS) {
            // Cooldown period elapsed: Transition to HALF_OPEN
            breaker.state = 'HALF_OPEN';
            breaker.lastStateChange = now;
        } else {
            // Still in cooldown: Fast reject
            return { allowed: false, reason: 'upstream_unavailable' };
        }
    }

    if (breaker.state === 'HALF_OPEN') {
        // Synchronously lock using probeInFlight flag in the same event-loop tick
        if (!breaker.probeInFlight) {
            breaker.probeInFlight = true;
            // Launch single synthetic health probe asynchronously in background
            launchSyntheticHealthProbe(origin, healthCheckPath);
        }
        // Real client requests continue to receive 503 during probe execution
        return { allowed: false, reason: 'upstream_unavailable' };
    }

    // State is CLOSED
    return { allowed: true };
}

/**
 * Tracks in-flight requests and response status codes for an active proxy connection.
 */
export function trackInFlightRequest(origin: string, res: Response | ServerResponse): () => void {
    const breaker = getOrCreateCircuitBreaker(origin);
    breaker.inFlight++;

    let released = false;
    const release = () => {
        if (!released) {
            released = true;
            breaker.inFlight = Math.max(0, breaker.inFlight - 1);
        }
    };

    res.on('finish', () => {
        release();
        if ((res as any).__aegisFailureRecorded) {
            return;
        }
        if (res.statusCode >= 500) {
            recordUpstreamFailure(origin);
        } else {
            recordUpstreamSuccess(origin);
        }
    });

    res.on('close', () => {
        release();
    });

    return release;
}

/**
 * Express middleware to enforce circuit breaker and bulkhead checks before forwarding downstream.
 */
export function createCircuitBreakerMiddleware(healthCheckPath?: string) {
    return (req: Request, res: Response, next: NextFunction): void => {
        const targetUrl = (req as any).targetUrl || (req as any).baseUrl;
        if (!targetUrl || typeof targetUrl !== 'string') {
            return next();
        }

        const origin = extractOrigin(targetUrl);
        if (!origin) {
            return next();
        }

        const result = checkCircuitAndBulkhead(origin, healthCheckPath);
        if (!result.allowed) {
            sendGatewayError(res, 503, result.reason, req);
            return;
        }

        trackInFlightRequest(origin, res);
        (req as any).upstreamOrigin = origin;
        next();
    };
}

/**
 * Standard proxy error handler to be attached to http-proxy-middleware instances.
 * Correctly increments circuit breaker failures and returns PRD v2.1 compliant errors.
 */
export function handleProxyError(
    err: any,
    req: Request,
    res: Response | ServerResponse,
    origin?: string
): void {
    const resolvedOrigin = origin || (req as any).upstreamOrigin || extractOrigin((req as any).targetUrl || '');
    if (resolvedOrigin) {
        (res as any).__aegisFailureRecorded = true;
        recordUpstreamFailure(resolvedOrigin);
    }

    if (res instanceof ServerResponse && !res.headersSent) {
        const errorCode = err?.code || '';
        const errorMessage = (err?.message || '').toLowerCase();

        // 504: Upstream Timeout
        if (errorCode === 'ETIMEDOUT' || errorCode === 'ESOCKETTIMEDOUT' || errorMessage.includes('timeout')) {
            sendGatewayError(res, 504, 'upstream_timeout', req);
            return;
        }

        // 503: Upstream Unavailable (Connection refused, network failure, SSRF block, etc.)
        sendGatewayError(res, 503, 'upstream_unavailable', req);
    }
}

/**
 * Diagnostics & testing helper to inspect circuit breaker status.
 */
export function getCircuitBreakerState(origin: string): Readonly<UpstreamCircuitBreaker> | undefined {
    return circuitBreakers.get(origin);
}

/**
 * Resets all circuit breakers in memory (used for tests/reloading).
 */
export function resetAllCircuitBreakers(): void {
    circuitBreakers.clear();
}
