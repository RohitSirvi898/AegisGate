import type { Request, Response, NextFunction } from 'express';
import { publishThreatLog } from '../config/queue.js';
import { redisClient } from '../config/redis.js';
import { sendGatewayError } from '../utils/errors.js';
import { getClientIp } from '../utils/ip.js';
import { recordAbuseEvent } from './ipJail.js';

/**
 * Fast Regex Threat Inspection patterns for blatant SQLi / XSS exploit patterns.
 */
const THREAT_PATTERNS: { name: string; regex: RegExp }[] = [
    { name: 'XSS Script Tag', regex: /<\/?script\b[^>]*>/i },
    { name: 'SQL Injection Boolean Bypass', regex: /'\s*OR\s+['"]?\w+['"]?\s*=\s*['"]?\w+/i },
    { name: 'SQL Injection OR 1=1', regex: /\bOR\s+['"]?1['"]?\s*=\s*['"]?1/i },
    { name: 'SQL Injection UNION SELECT', regex: /\bUNION\s+(?:ALL\s+)?SELECT\b/i },
    { name: 'SQL Comment Dashes', regex: /--/ },
    { name: 'SQL Block Comment', regex: /\/\*[\s\S]*?\*\// }
];

/**
 * Inline, synchronous edge security filter:
 * 1. Payload Body Cap Check: Rejects bodies > 100KB with 413 Payload Too Large.
 * 2. Fast Regex Threat Inspection: Scans body string for SQLi / XSS patterns.
 * 3. On attack pattern detection:
 *    - Increments Redis abuse score via recordAbuseEvent().
 *    - Dispatches threat event asynchronously to RabbitMQ via setImmediate().
 *    - Immediately drops request with HTTP 403 'request_blocked'.
 * 4. On clean payload: Calls next() immediately without blocking.
 */
export const securityFilter = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    // Exempt control plane and admin routes from abuse tracking and edge filtering
    if (
        req.path.startsWith('/api/v1/admin') ||
        req.path.startsWith('/api/v1/analytics') ||
        req.originalUrl?.startsWith('/api/v1/admin') ||
        req.originalUrl?.startsWith('/api/v1/analytics')
    ) {
        return next();
    }

    try {
        let bodyStr = '';
        const clientIp = (req as any).clientIp || getClientIp(req);
        (req as any).clientIp = clientIp;

        // 1. Payload Body Cap Check (100KB = 100 * 1024 bytes)
        if (req.body !== undefined && req.body !== null) {
            try {
                bodyStr = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
            } catch {
                bodyStr = '';
            }

            if (bodyStr.length > 100 * 1024) {
                sendGatewayError(res, 413, 'payload_too_large', req);
                return;
            }
        } else if (req.query && Object.keys(req.query).length > 0) {
            bodyStr = JSON.stringify(req.query);
        }

        // 2. Fast Regex Threat Inspection
        if (bodyStr) {
            let matchedThreat: string | null = null;
            for (const pattern of THREAT_PATTERNS) {
                if (pattern.regex.test(bodyStr)) {
                    matchedThreat = pattern.name;
                    break;
                }
            }

            if (matchedThreat) {
                const headerKey = req.headers['x-aegis-api-key'];
                let finalProjectId = (req as any).projectId || 'aegis_default_project';
                let slackWebhookUrl = (req as any).slackWebhookUrl || '';
                let discordWebhookUrl = (req as any).discordWebhookUrl || '';

                if (headerKey && typeof headerKey === 'string' && !(req as any).projectId) {
                    try {
                        const cached = await redisClient.get(`project:${headerKey.trim()}`);
                        if (cached) {
                            const parsed = JSON.parse(cached);
                            finalProjectId = parsed.projectId || finalProjectId;
                            slackWebhookUrl = parsed.slackWebhookUrl || '';
                            discordWebhookUrl = parsed.discordWebhookUrl || '';
                        }
                    } catch (err: any) {
                        console.error('[Security Filter Project Resolution] Fallback to default project:', err.message);
                    }
                }

                // Increment IP abuse score in Redis (auto-jails if threshold reached)
                recordAbuseEvent(clientIp, 1).catch(err => {
                    console.error('[Abuse Scoring Background Error]:', err?.message || err);
                });

                // Asynchronously dispatch threat event to RabbitMQ for telemetry logging
                setImmediate(() => {
                    publishThreatLog({
                        projectId: finalProjectId,
                        clientIp,
                        endpoint: req.originalUrl || req.url || '',
                        method: req.method,
                        timestamp: new Date().toISOString(),
                        rawBody: bodyStr,
                        attackVector: matchedThreat,
                        severity: 'HIGH',
                        summary: `Request blocked by AegisGate Security Filter regex match: ${matchedThreat}`,
                        slackWebhookUrl,
                        discordWebhookUrl
                    }).catch((err) => {
                        console.error('[Background Threat Publish Fault]:', err);
                    });
                });

                // Immediately drop the request with HTTP 403 request_blocked
                sendGatewayError(res, 403, 'request_blocked', req);
                return;
            }
        }

        // Clean payload, proceed downstream immediately
        return next();
    } catch (error: any) {
        console.error('[Security Filter Internal Fault - Fail-Closed]:', error?.message || error);
        sendGatewayError(res, 503, 'upstream_unavailable', req);
        return;
    }
};

// Backwards-compatibility alias
export { securityFilter as aiFirewall };
