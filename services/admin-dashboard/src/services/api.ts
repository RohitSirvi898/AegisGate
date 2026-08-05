const baseURL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8080';

export interface Project {
    _id: string;
    projectName: string;
    apiKey: string;
    targetUrl?: string;
    dryRun: boolean;
    enableLLMAudit: boolean;
    slackWebhookUrl: string;
    discordWebhookUrl: string;
    createdAt?: string;
}

export interface DeadLetterLog {
    _id: string;
    projectId: string;
    clientIp?: string;
    endpoint?: string;
    method?: string;
    timestamp: string;
    rawBody?: string;
    errorReason?: string;
    retryCount?: number;
    payload?: any;
    createdAt?: string;
}

/**
 * Updates settings for a specified tenant project.
 */
export const updateProjectSettings = async (
    projectId: string,
    settings: Partial<Project>,
    token: string
): Promise<Project> => {
    const response = await fetch(`${baseURL}/api/v1/projects/${projectId}`, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(settings)
    });

    if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.message || `Failed to update project settings (HTTP ${response.status})`);
    }

    return response.json();
};

/**
 * Fetches unprocessable poison messages held in the Dead-Letter Queue (DLQ).
 */
export const fetchDeadLetterLogs = async (
    projectId: string,
    token: string
): Promise<DeadLetterLog[]> => {
    try {
        const response = await fetch(`${baseURL}/api/v1/analytics/dlq`, {
            headers: {
                'X-Project-Id': projectId,
                'Authorization': `Bearer ${token}`
            },
            signal: AbortSignal.timeout(3000)
        });

        if (!response.ok) {
            throw new Error(`HTTP Error ${response.status}`);
        }

        const data = await response.json();
        return Array.isArray(data) ? data : data.logs || [];
    } catch {
        // Return empty array for graceful offline fallback
        return [];
    }
};

/**
 * Re-queues a dead-lettered poison message back into the primary AegisGate pipeline.
 */
export const retryDeadLetterMessage = async (
    messageId: string,
    token: string
): Promise<void> => {
    const response = await fetch(`${baseURL}/api/v1/analytics/dlq/${messageId}/retry`, {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${token}`
        }
    });

    if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.message || `Failed to re-queue message ${messageId}`);
    }
};

/**
 * Permanently purges a dead-lettered poison message from the DLQ.
 */
export const purgeDeadLetterMessage = async (
    messageId: string,
    token: string
): Promise<void> => {
    const response = await fetch(`${baseURL}/api/v1/analytics/dlq/${messageId}`, {
        method: 'DELETE',
        headers: {
            'Authorization': `Bearer ${token}`
        }
    });

    if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.message || `Failed to purge message ${messageId}`);
    }
};
