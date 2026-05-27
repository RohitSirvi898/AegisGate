import type { Request, Response, NextFunction } from 'express';
import { publishThreatLog } from '../config/queue.js';

const AI_ANOMALY_ENGINE_URL = process.env.AI_ANOMALY_ENGINE_URL || 'http://localhost:8000/analyze';
const AI_INFERENCE_TIMEOUT_MS = parseInt(process.env.AI_INFERENCE_TIMEOUT_MS || '200', 10);

/**
 * High-performance structural metadata extractor that processes a request body string.
 * Returns a 4-element array of float metrics:
 *   Index 0: Total string length of the raw request body.
 *   Index 1: Count of injection-sensitive special characters: single quotes ('), double quotes ("), semicolons (;), and hyphens (-).
 *   Index 2: Estimated JSON key count by counting the total number of structural colons (:).
 *   Index 3: Maximum curly brace {} nesting depth.
 */
export const extractStructuralMetrics = (bodyStr: string): number[] => {
    const totalLength = bodyStr.length;
    let injectionCharCount = 0;
    let colonCount = 0;
    let maxNestingDepth = 0;
    let currentNestingDepth = 0;

    for (let i = 0; i < totalLength; i++) {
        const char = bodyStr[i];

        // Index 1: Count of injection-sensitive special characters (', ", ;, -)
        if (char === "'" || char === '"' || char === ';' || char === '-') {
            injectionCharCount++;
        }

        // Index 2: Estimated JSON key count (counting structural colons)
        if (char === ':') {
            colonCount++;
        }

        // Index 3: Maximum curly brace {} nesting depth tracking
        if (char === '{') {
            currentNestingDepth++;
            if (currentNestingDepth > maxNestingDepth) {
                maxNestingDepth = currentNestingDepth;
            }
        } else if (char === '}') {
            currentNestingDepth--;
        }
    }

    return [
        totalLength,
        injectionCharCount,
        colonCount,
        maxNestingDepth
    ];
};

/**
 * Express middleware that intercepts incoming POST/PUT payloads and processes them through
 * an inline Machine Learning anomaly engine.
 */
export const aiFirewall = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    // Process GET, POST, and PUT requests
    if (req.method !== 'GET' && req.method !== 'POST' && req.method !== 'PUT') {
        return next();
    }

    try {
        // Extract structural metadata metrics depending on the HTTP verb
        let bodyStr = '';
        if (req.method === 'POST' || req.method === 'PUT') {
            bodyStr = JSON.stringify(req.body || {});
        } else if (req.method === 'GET') {
            bodyStr = JSON.stringify(req.query || {});
        }

        // Extract the 4-element metrics array
        const metrics = extractStructuralMetrics(bodyStr);

        // Issue fast POST to AI_ANOMALY_ENGINE_URL with configured timeout
        const response = await fetch(AI_ANOMALY_ENGINE_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ metrics }),
            signal: AbortSignal.timeout(AI_INFERENCE_TIMEOUT_MS)
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json() as { is_anomaly: boolean };

        // If anomaly detected, terminate and return HTTP 403 Forbidden
        if (data.is_anomaly) {
            // Asynchronous, un-awaited background promise to publish threat details
            publishThreatLog({
                clientIp: req.ip || req.socket.remoteAddress || 'unknown-client',
                endpoint: req.originalUrl || req.url || '',
                method: req.method,
                timestamp: new Date().toISOString(),
                rawBody: bodyStr
            }).catch((err) => {
                console.error('[Background Threat Publish Fault] Fail-open trace:', err);
            });

            res.status(403).json({
                error: 'Malicious Payload Detected',
                message: 'Security boundary blocked request due to structural anomalies.'
            });
            return;
        }

        // Safe payload, pass downstream
        next();
    } catch (error: any) {
        // Fail-Open Resilience Strategy
        console.warn('[AI Firewall Timeout/Failure - Bypassing Engine Protection Safely]');
        console.log('AI Firewall raw error:', error?.message || error);
        next();
    }
};
