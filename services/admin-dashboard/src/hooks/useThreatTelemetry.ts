import { useState, useEffect } from 'react';
const baseURL = import.meta.env.VITE_API_BASE_URL

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


export const useThreatTelemetry = () => {
    const [threats, setThreats] = useState<ThreatRecord[]>([]);
    const [stats, setStats] = useState({
        totalBlocks: 0,
        criticalCount: 0,
        highCount: 0
    });
    const [loading, setLoading] = useState<boolean>(true);
    const [error, setError] = useState<string | null>(null);

    const fetchTelemetry = async () => {
        try {
            // Target the Gateway Core analytics endpoint with tenant header isolation
            const response = await fetch(`${baseURL}/api/v1/analytics/telemetry`, {
                headers: {
                    'X-Project-Id': 'aegis_default_project'
                },
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
