import { useState, useEffect } from 'react';

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

// Realistic pre-populated threat logs to showcase when the local database starts empty
const DEFAULT_FALLBACK_THREATS: ThreatRecord[] = [
    {
        _id: "log_001",
        clientIp: "192.168.1.105",
        endpoint: "/api/v1/payments",
        method: "POST",
        timestamp: new Date(Date.now() - 4000).toISOString(),
        rawBody: '{"cardNumber": "4111********1111", "cvv": "\' OR 1=1 --", "amount": 250000}',
        attackVector: "SQL Injection",
        severity: "CRITICAL",
        summary: "Malformed SQL query statements identified inside credit card payment parameters."
    },
    {
        _id: "log_002",
        clientIp: "103.88.22.41",
        endpoint: "/api/v1/users",
        method: "POST",
        timestamp: new Date(Date.now() - 12000).toISOString(),
        rawBody: '{"username": "<script>alert(document.cookie)</script>", "email": "hacker@shield.io"}',
        attackVector: "XSS",
        severity: "HIGH",
        summary: "Cross-Site Scripting attack vector detected in username registration payload."
    },
    {
        _id: "log_003",
        clientIp: "198.51.100.72",
        endpoint: "/api/v1/payments",
        method: "PUT",
        timestamp: new Date(Date.now() - 25000).toISOString(),
        rawBody: '{"transactionId": "../../../etc/passwd", "status": "retry"}',
        attackVector: "Directory Traversal",
        severity: "HIGH",
        summary: "Path traversal character sequences identified inside transaction parameters."
    },
    {
        _id: "log_004",
        clientIp: "203.0.113.88",
        endpoint: "/api/v1/users",
        method: "GET",
        timestamp: new Date(Date.now() - 45000).toISOString(),
        rawBody: '{"query": "{\\"$gt\\": \\"\\"}}"}',
        attackVector: "NoSQL Injection",
        severity: "MEDIUM",
        summary: "Suspicious NoSQL syntax identified in query parameter mapping."
    },
    {
        _id: "log_005",
        clientIp: "192.168.1.14",
        endpoint: "/api/v1/users",
        method: "POST",
        timestamp: new Date(Date.now() - 90000).toISOString(),
        rawBody: '{"test": "normal_object_data"}',
        attackVector: "Unknown Anomaly",
        severity: "LOW",
        summary: "Structural outlier metrics flagged by Isolation Forest edge detection."
    }
];

export const useThreatTelemetry = () => {
    const [threats, setThreats] = useState<ThreatRecord[]>(DEFAULT_FALLBACK_THREATS);
    const [stats, setStats] = useState({
        totalBlocks: DEFAULT_FALLBACK_THREATS.length,
        criticalCount: DEFAULT_FALLBACK_THREATS.filter(t => t.severity === 'CRITICAL').length,
        highCount: DEFAULT_FALLBACK_THREATS.filter(t => t.severity === 'HIGH').length
    });
    const [loading, setLoading] = useState<boolean>(true);
    const [error, setError] = useState<string | null>(null);

    const fetchTelemetry = async () => {
        try {
            // Target the Gateway Core analytics endpoint
            const response = await fetch('http://localhost:8080/api/v1/analytics/telemetry', {
                signal: AbortSignal.timeout(3000)
            });

            if (!response.ok) {
                throw new Error(`Server returned HTTP ${response.status}`);
            }

            const data = await response.json() as {
                totalBlocks: number;
                criticalCount: number;
                highCount: number;
                logs: ThreatRecord[];
            };

            setThreats(data.logs && data.logs.length > 0 ? data.logs : DEFAULT_FALLBACK_THREATS);
            setStats({
                totalBlocks: data.totalBlocks || 0,
                criticalCount: data.criticalCount || 0,
                highCount: data.highCount || 0
            });
            setError(null);
        } catch (err: any) {
            // Keep drawing the fallback logs so the console is always interactive,
            // but store the error in case the admin console needs to display connectivity status
            setError(`Backend offline. Running in Simulation Mode.`);
            setThreats(DEFAULT_FALLBACK_THREATS);
            setStats({
                totalBlocks: DEFAULT_FALLBACK_THREATS.length,
                criticalCount: DEFAULT_FALLBACK_THREATS.filter(t => t.severity === 'CRITICAL').length,
                highCount: DEFAULT_FALLBACK_THREATS.filter(t => t.severity === 'HIGH').length
            });
            console.log('📡 [Dashboard Telemetry Polling] Server unreachable. Displaying local telemetry stream.');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        // Run first fetch immediately
        fetchTelemetry();

        // Performance-tuned polling routine: refresh exactly every 5 seconds
        const intervalId = setInterval(fetchTelemetry, 5000);

        return () => {
            clearInterval(intervalId);
        };
    }, []);

    return {
        threats,
        stats,
        loading,
        error,
        refetch: fetchTelemetry
    };
};
