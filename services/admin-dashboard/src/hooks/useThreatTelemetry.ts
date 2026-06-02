import { useState, useEffect } from 'react';

const baseURL = import.meta.env.VITE_API_BASE_URL;

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

export const useThreatTelemetry = (activeProjectId: string | null, token: string | null) => {
    const [threats, setThreats] = useState<ThreatRecord[]>([]);
    const [stats, setStats] = useState({
        totalBlocks: 0,
        criticalCount: 0,
        highCount: 0
    });
    const [loading, setLoading] = useState<boolean>(true);
    const [error, setError] = useState<string | null>(null);

    const fetchTelemetry = async () => {
        // Guard clause at the top: if no activeProjectId or token, do not fetch
        if (!activeProjectId || !token) {
            setLoading(false);
            return;
        }

        try {
            const headers: Record<string, string> = {
                'X-Project-Id': activeProjectId,
                'Authorization': `Bearer ${token}`
            };

            // Target the Gateway Core analytics endpoint with tenant header isolation
            const response = await fetch(`${baseURL}/api/v1/analytics/telemetry`, {
                headers,
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

            setThreats(data.logs && data.logs.length > 0 ? data.logs : []);
            setStats({
                totalBlocks: data.totalBlocks || 0,
                criticalCount: data.criticalCount || 0,
                highCount: data.highCount || 0
            });
            setError(null);
        } catch (err: any) {
            setError(`Backend offline. Running in Simulation Mode.`);
            setThreats([]);
            setStats({
                totalBlocks: 0,
                criticalCount: 0,
                highCount: 0
            });
            console.log('📡 [Dashboard Telemetry Polling] Server unreachable. Displaying local telemetry stream.');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        // Guard clause at the top of hook effect execution
        if (!activeProjectId || !token) {
            setLoading(false);
            return;
        }

        // Run first fetch immediately
        fetchTelemetry();

        // Performance-tuned polling routine: refresh exactly every 5 seconds
        const intervalId = setInterval(() => {
            if (!activeProjectId || !token) return;
            fetchTelemetry();
        }, 5000);

        return () => {
            clearInterval(intervalId);
        };
    }, [token, activeProjectId]); // Re-poll cleanly when credentials or project changes

    return {
        threats,
        stats,
        loading,
        error,
        refetch: fetchTelemetry
    };
};
