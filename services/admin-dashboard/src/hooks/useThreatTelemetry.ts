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

export type ConnectionStatus = 'connected' | 'online' | 'rate_limited' | 'reconnecting' | 'offline' | 'unauthenticated';

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

export const getStoredToken = (): string | null => {
    try {
        if (typeof localStorage !== 'undefined') {
            const t = localStorage.getItem('aegis_token');
            if (t) return t;
        }
    } catch {
        // ignore
    }
    try {
        if (typeof sessionStorage !== 'undefined') {
            const t = sessionStorage.getItem('aegis_token');
            if (t) return t;
        }
    } catch {
        // ignore
    }
    return null;
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

            // 1. Pre-flight Auth Check: verify an auth token exists and that the user is authenticated
            const currentToken = token || getStoredToken();
            if (!currentToken) {
                setConnectionStatus('unauthenticated');
                setLoading(false);
                return; // Skip poll completely if unauthenticated
            }

            // 2. Offline Check: skip poll cycle if client is disconnected
            if (typeof navigator !== 'undefined' && !navigator.onLine) {
                setConnectionStatus('offline');
                setLoading(false);
                return;
            }

            isFetching = true;
            let nextDelayMs = 5000;
            let is401Unauthorized = false;

            try {
                const telemetryPromise: Promise<TelemetryResponse | null> =
                    activeProjectId
                        ? fetchTelemetry(activeProjectId, currentToken)
                        : Promise.resolve(null);

                const breakersPromise: Promise<CircuitBreakerRecord[]> =
                    fetchCircuitBreakers(currentToken);

                const jailedPromise: Promise<JailedIpRecord[]> =
                    fetchJailedIps(currentToken);

                // Fetch telemetry, circuit breakers, and jailed IPs in a single bundled cycle via Promise.allSettled
                const [telemetryResult, breakersResult, jailedResult] = await Promise.allSettled([
                    telemetryPromise,
                    breakersPromise,
                    jailedPromise
                ]);

                if (!isMounted) return;

                const results = [telemetryResult, breakersResult, jailedResult];

                // 3. 401 Circuit Trip: Wrap polling network resolution in a 401 status check
                for (const res of results) {
                    if (res.status === 'rejected') {
                        const reason = res.reason;
                        if (reason?.status === 401 || reason?.message?.includes('401')) {
                            is401Unauthorized = true;
                            break;
                        }
                    }
                }

                if (is401Unauthorized) {
                    if (timeoutId) {
                        clearTimeout(timeoutId);
                        timeoutId = null;
                    }
                    setConnectionStatus('unauthenticated');
                    setError('Session expired or unauthorized (401). Please sign in.');
                    // Stop future scheduled polls completely
                    return;
                }

                // 4. Check if any endpoint received a 429 Too Many Requests response
                let isRateLimited = false;
                let retryAfterSec = 10;

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

                // 5. Process fulfilled responses
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
                }

                if (breakersResult.status === 'fulfilled') {
                    setCircuitBreakers(breakersResult.value || []);
                    anySuccess = true;
                } else {
                    anyFailure = true;
                }

                if (jailedResult.status === 'fulfilled') {
                    setJailedList(formatJailedIps(jailedResult.value || []));
                    anySuccess = true;
                } else {
                    anyFailure = true;
                }

                if (anySuccess) {
                    setConnectionStatus('connected');
                    setError(null);
                } else if (anyFailure) {
                    setConnectionStatus('reconnecting');
                    setError('Reconnecting...');
                }
            } catch (err: any) {
                if (!isMounted) return;
                if (err?.status === 401 || err?.message?.includes('401')) {
                    is401Unauthorized = true;
                    setConnectionStatus('unauthenticated');
                    setError('Session expired or unauthorized (401). Please sign in.');
                    return;
                }
                if (typeof navigator !== 'undefined' && !navigator.onLine) {
                    setConnectionStatus('offline');
                    return;
                }
                setConnectionStatus('reconnecting');
                setError('Reconnecting...');
            } finally {
                if (isMounted) {
                    setLoading(false);
                    isFetching = false;
                    const isOffline = typeof navigator !== 'undefined' && !navigator.onLine;
                    if (!isOffline && !is401Unauthorized) {
                        timeoutId = setTimeout(() => {
                            poll();
                        }, nextDelayMs);
                    }
                }
            }
        };

        // Network connectivity event handlers
        const handleOnline = () => {
            const currentToken = token || getStoredToken();
            if (!currentToken) {
                setConnectionStatus('unauthenticated');
                return;
            }
            setConnectionStatus('connected');
            setError(null);
            if (timeoutId) {
                clearTimeout(timeoutId);
                timeoutId = null;
            }
            poll(); // Immediately refresh when connectivity returns
        };

        const handleOffline = () => {
            setConnectionStatus('offline');
            if (timeoutId) {
                clearTimeout(timeoutId);
                timeoutId = null;
            }
        };

        if (typeof window !== 'undefined') {
            window.addEventListener('online', handleOnline);
            window.addEventListener('offline', handleOffline);
        }

        // Run initial pre-flight check and poll
        poll();

        return () => {
            isMounted = false;
            if (typeof window !== 'undefined') {
                window.removeEventListener('online', handleOnline);
                window.removeEventListener('offline', handleOffline);
            }
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
