import { useState, useEffect } from 'react';
import {
    fetchTelemetry,
    fetchCircuitBreakers,
    fetchJailedIps,
    type JailedIpRecord,
    type CircuitBreakerRecord,
    type TelemetryResponse,
    ApiError
} from '../services/api';

export interface ThreatRecord {
    _id: string;
    clientIp: string;
    endpoint: string;
    method: string;
    timestamp: string;
    rawBody?: string;
    attackVector: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | string;
    summary: string;
}

export interface PrototypeJailItem {
    ip: string;
    timeRemaining: string;
    pct: number;
    trigger: string;
    lastRequest: string;
}

export type ConnectionStatus = 'connected' | 'rate_limited' | 'reconnecting';

export const formatJailedIps = (ips: JailedIpRecord[]): PrototypeJailItem[] => {
    return ips.map((item) => {
        const ttlSec = item.ttl || 300;
        const mins = Math.floor(ttlSec / 60);
        const secs = ttlSec % 60;
        const timeRemaining = `${mins}m ${secs < 10 ? '0' : ''}${secs}s`;
        const pct = Math.min(100, Math.round((ttlSec / 600) * 100));
        return {
            ip: item.ip,
            timeRemaining,
            pct,
            trigger: 'Rate limit / Signature rule',
            lastRequest: 'Blocked at edge'
        };
    });
};

export const useThreatTelemetry = (activeProjectId: string | null, token: string | null) => {
    const [threats, setThreats] = useState<ThreatRecord[]>([]);
    const [stats, setStats] = useState({
        totalBlocks: 0,
        criticalCount: 0,
        highCount: 0
    });
    const [circuitBreakers, setCircuitBreakers] = useState<CircuitBreakerRecord[]>([]);
    const [jailedList, setJailedList] = useState<PrototypeJailItem[]>([]);
    const [connectionStatus, setConnectionStatus] = useState<ConnectionStatus>('connected');
    const [loading, setLoading] = useState<boolean>(true);
    const [error, setError] = useState<string | null>(null);
    const [triggerCount, setTriggerCount] = useState<number>(0);

    useEffect(() => {
        let isMounted = true;
        let timeoutId: ReturnType<typeof setTimeout> | null = null;
        let isFetching = false;

        const poll = async () => {
            if (isFetching) return;
            isFetching = true;

            let nextDelayMs = 5000;

            try {
                const telemetryPromise: Promise<TelemetryResponse | null> =
                    activeProjectId && token
                        ? fetchTelemetry(activeProjectId, token)
                        : Promise.resolve(null);

                const breakersPromise: Promise<CircuitBreakerRecord[]> =
                    fetchCircuitBreakers(token || undefined);

                const jailedPromise: Promise<JailedIpRecord[]> =
                    fetchJailedIps(token || undefined);

                // Fetch telemetry, circuit breakers, and jailed IPs in a single bundled cycle via Promise.allSettled
                const [telemetryResult, breakersResult, jailedResult] = await Promise.allSettled([
                    telemetryPromise,
                    breakersPromise,
                    jailedPromise
                ]);

                if (!isMounted) return;

                // Check if any endpoint received a 429 Too Many Requests response
                let isRateLimited = false;
                let retryAfterSec = 10;

                const results = [telemetryResult, breakersResult, jailedResult];
                for (const res of results) {
                    if (res.status === 'rejected') {
                        const reason = res.reason;
                        if (reason instanceof ApiError && reason.status === 429) {
                            isRateLimited = true;
                            if (reason.retryAfter && reason.retryAfter > 0) {
                                retryAfterSec = Math.max(retryAfterSec, reason.retryAfter);
                            }
                        } else if (reason?.status === 429 || reason?.message?.includes('429')) {
                            isRateLimited = true;
                            const parsed = parseInt(reason?.retryAfter, 10);
                            if (!isNaN(parsed) && parsed > 0) {
                                retryAfterSec = Math.max(retryAfterSec, parsed);
                            }
                        }
                    }
                }

                if (isRateLimited) {
                    setConnectionStatus('rate_limited');
                    setError(`Sync paused (rate limited). Resuming in ${retryAfterSec}s...`);
                    // Halt polling until the window resets rather than continuously retrying
                    nextDelayMs = retryAfterSec * 1000;
                    // Retain whatever live data was previously loaded (do not overwrite with mock fixtures)
                    return;
                }

                // Process fulfilled responses
                let anySuccess = false;
                let anyFailure = false;

                if (telemetryResult.status === 'fulfilled') {
                    if (telemetryResult.value) {
                        const data = telemetryResult.value;
                        setThreats(data.logs && data.logs.length > 0 ? data.logs : []);
                        setStats({
                            totalBlocks: data.totalBlocks || 0,
                            criticalCount: data.criticalCount || 0,
                            highCount: data.highCount || 0
                        });
                        anySuccess = true;
                    }
                } else {
                    anyFailure = true;
                    // Retain live data on error
                }

                if (breakersResult.status === 'fulfilled') {
                    setCircuitBreakers(breakersResult.value || []);
                    anySuccess = true;
                } else {
                    anyFailure = true;
                    // Retain live data on error
                }

                if (jailedResult.status === 'fulfilled') {
                    setJailedList(formatJailedIps(jailedResult.value || []));
                    anySuccess = true;
                } else {
                    anyFailure = true;
                    // Retain live data on error
                }

                if (anySuccess) {
                    setConnectionStatus('connected');
                    setError(null);
                } else if (anyFailure) {
                    setConnectionStatus('reconnecting');
                    setError('Reconnecting...');
                }
            } catch {
                if (!isMounted) return;
                setConnectionStatus('reconnecting');
                setError('Reconnecting...');
            } finally {
                if (isMounted) {
                    setLoading(false);
                    isFetching = false;
                    timeoutId = setTimeout(() => {
                        poll();
                    }, nextDelayMs);
                }
            }
        };

        // Run immediate initial fetch
        poll();

        return () => {
            isMounted = false;
            if (timeoutId) {
                clearTimeout(timeoutId);
                timeoutId = null;
            }
        };
    }, [activeProjectId, token, triggerCount]);

    const refetch = async () => {
        setTriggerCount((prev) => prev + 1);
    };

    return {
        threats,
        stats,
        circuitBreakers,
        setCircuitBreakers,
        jailedList,
        setJailedList,
        connectionStatus,
        loading,
        error,
        refetch
    };
};
