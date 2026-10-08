const getEnvVar = (key: string): string | undefined => {
  try {
    if (typeof import.meta !== 'undefined' && (import.meta as any).env && (import.meta as any).env[key]) {
      return (import.meta as any).env[key];
    }
  } catch {
    // Environment lookup fallback
  }
  try {
    const proc = (globalThis as any).process;
    if (proc && proc.env && proc.env[key]) {
      return proc.env[key];
    }
  } catch {
    // Global process lookup fallback
  }
  return undefined;
};

const baseURL = getEnvVar('VITE_GATEWAY_URL') || getEnvVar('VITE_API_BASE_URL') || 'http://localhost:8080';

export const getAuthHeader = (): Record<string, string> => {
  let token: string | null = null;
  try {
    if (typeof localStorage !== 'undefined') {
      token = localStorage.getItem('aegis_token');
    }
  } catch {
    // Local storage access fallback
  }
  try {
    if (!token && typeof sessionStorage !== 'undefined') {
      token = sessionStorage.getItem('aegis_token');
    }
  } catch {
    // Session storage access fallback
  }
  return token ? { Authorization: `Bearer ${token}` } : {};
};

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

export interface JailedIpRecord {
  ip: string;
  ttl: number;
}

export interface CircuitBreakerRecord {
  origin: string;
  state: 'CLOSED' | 'OPEN' | 'HALF_OPEN';
  consecutiveFailures: number;
  inFlight: number;
  lastStateChange: number;
}

export interface TelemetryResponse {
  totalBlocks: number;
  criticalCount: number;
  highCount: number;
  logs: any[];
}

export const fetchProjects = async (token?: string): Promise<Project[]> => {
  try {
    const response = await fetch(`${baseURL}/api/v1/projects`, {
      headers: {
        ...getAuthHeader(),
        ...(token ? { Authorization: `Bearer ${token}` } : {})
      }
    });
    if (!response.ok) {
      return [];
    }
    return await response.json();
  } catch {
    return [];
  }
};

export const createProject = async (
  params: { name?: string; projectName?: string },
  token?: string
): Promise<Project> => {
  const projectName = (params.projectName || params.name || '').trim();
  const response = await fetch(`${baseURL}/api/v1/projects`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...getAuthHeader(),
      ...(token ? { Authorization: `Bearer ${token}` } : {})
    },
    body: JSON.stringify({ projectName })
  });

  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.message || `Failed to create project (HTTP ${response.status})`);
  }

  return response.json();
};

export const updateProjectSettings = async (
  projectId: string,
  settings: Partial<Project>,
  token?: string
): Promise<Project> => {
  const response = await fetch(`${baseURL}/api/v1/projects/${projectId}`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      ...getAuthHeader(),
      ...(token ? { Authorization: `Bearer ${token}` } : {})
    },
    body: JSON.stringify(settings)
  });

  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.message || `Failed to update project settings (HTTP ${response.status})`);
  }

  return response.json();
};

export const fetchDeadLetterLogs = async (
  projectId: string,
  token?: string
): Promise<DeadLetterLog[]> => {
  try {
    const response = await fetch(`${baseURL}/api/v1/analytics/dlq`, {
      headers: {
        'X-Project-Id': projectId,
        ...getAuthHeader(),
        ...(token ? { Authorization: `Bearer ${token}` } : {})
      },
      signal: AbortSignal.timeout(3000)
    });

    if (!response.ok) {
      throw new Error(`HTTP Error ${response.status}`);
    }

    const data = await response.json();
    return Array.isArray(data) ? data : data.logs || [];
  } catch {
    return [];
  }
};

export const fetchDlqStats = async (projectId?: string, token?: string): Promise<{ count: number }> => {
  const headers: Record<string, string> = {
    ...getAuthHeader(),
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(projectId ? { 'X-Project-Id': projectId } : {})
  };
  const response = await fetch(`${baseURL}/api/v1/analytics/dlq`, {
    headers,
    signal: AbortSignal.timeout(3000)
  });
  if (!response.ok) {
    throw new ApiError(`Failed to fetch DLQ stats: ${response.status}`, response.status);
  }
  const data = await response.json();
  const count = Array.isArray(data) ? data.length : (Array.isArray(data.logs) ? data.logs.length : 0);
  return { count };
};

export const retryDeadLetterMessage = async (
  messageId: string,
  token?: string
): Promise<void> => {
  const response = await fetch(`${baseURL}/api/v1/analytics/dlq/${messageId}/retry`, {
    method: 'POST',
    headers: {
      ...getAuthHeader(),
      ...(token ? { Authorization: `Bearer ${token}` } : {})
    }
  });

  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.message || `Failed to re-queue message ${messageId}`);
  }
};

export const purgeDeadLetterMessage = async (
  messageId: string,
  token?: string
): Promise<void> => {
  const response = await fetch(`${baseURL}/api/v1/analytics/dlq/${messageId}`, {
    method: 'DELETE',
    headers: {
      ...getAuthHeader(),
      ...(token ? { Authorization: `Bearer ${token}` } : {})
    }
  });

  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.message || `Failed to purge message ${messageId}`);
  }
};

export class ApiError extends Error {
  status: number;
  retryAfter?: number;

  constructor(message: string, status: number, retryAfter?: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.retryAfter = retryAfter;
  }
}

const parseRetryAfter = (response: Response): number | undefined => {
  const header = response.headers.get('Retry-After');
  if (header) {
    const val = parseInt(header, 10);
    if (!isNaN(val) && val > 0) return val;
  }
  return undefined;
};

export const fetchJailedIps = async (token?: string): Promise<JailedIpRecord[]> => {
  const headers: Record<string, string> = {
    ...getAuthHeader(),
    ...(token ? { Authorization: `Bearer ${token}` } : {})
  };
  const response = await fetch(`${baseURL}/api/v1/admin/jailed-ips`, {
    headers,
    signal: AbortSignal.timeout(3000)
  });
  if (!response.ok) {
    throw new ApiError(`Failed to fetch jailed IPs: ${response.status}`, response.status, parseRetryAfter(response));
  }
  const data = await response.json();
  return Array.isArray(data.jailedIps) ? data.jailedIps : [];
};

export const unbanClientIp = async (ip: string, token?: string): Promise<void> => {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...getAuthHeader(),
    ...(token ? { Authorization: `Bearer ${token}` } : {})
  };
  const response = await fetch(`${baseURL}/api/v1/admin/unban`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ ip })
  });
  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.message || `Failed to unban IP ${ip}`);
  }
};

export const fetchCircuitBreakers = async (token?: string): Promise<CircuitBreakerRecord[]> => {
  const headers: Record<string, string> = {
    ...getAuthHeader(),
    ...(token ? { Authorization: `Bearer ${token}` } : {})
  };
  const response = await fetch(`${baseURL}/api/v1/admin/circuit-breakers`, {
    headers,
    signal: AbortSignal.timeout(3000)
  });
  if (!response.ok) {
    throw new ApiError(`Failed to fetch circuit breakers: ${response.status}`, response.status, parseRetryAfter(response));
  }
  const data = await response.json();
  return Array.isArray(data.circuitBreakers) ? data.circuitBreakers : [];
};

export const fetchTelemetry = async (projectId: string, token?: string): Promise<TelemetryResponse> => {
  const headers: Record<string, string> = {
    'X-Project-Id': projectId,
    ...getAuthHeader(),
    ...(token ? { Authorization: `Bearer ${token}` } : {})
  };
  const response = await fetch(`${baseURL}/api/v1/analytics/telemetry`, {
    headers,
    signal: AbortSignal.timeout(3000)
  });
  if (!response.ok) {
    throw new ApiError(`Failed to fetch telemetry: ${response.status}`, response.status, parseRetryAfter(response));
  }
  return response.json();
};

export const login = async (credentials: { email: string; password: string }): Promise<{ token: string }> => {
  const response = await fetch(`${baseURL}/api/v1/auth/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      email: credentials.email.trim(),
      password: credentials.password.trim()
    })
  });
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.message || `HTTP error ${response.status}`);
  }
  return data;
};

export const register = async (credentials: { email: string; password: string }): Promise<{ token: string }> => {
  const response = await fetch(`${baseURL}/api/v1/auth/register`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      email: credentials.email.trim(),
      password: credentials.password.trim()
    })
  });
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.message || `HTTP error ${response.status}`);
  }
  return data;
};

export const getProjects = fetchProjects;
export const updateProject = updateProjectSettings;
export const getJailedIps = fetchJailedIps;
export const unbanIp = unbanClientIp;
export const getCircuitBreakers = fetchCircuitBreakers;
export const getTelemetry = fetchTelemetry;
export const getDlqStats = fetchDlqStats;

export const api = {
  getAuthHeader,
  getProjects,
  fetchProjects,
  createProject,
  updateProject,
  updateProjectSettings,
  getJailedIps,
  fetchJailedIps,
  unbanIp,
  unbanClientIp,
  getCircuitBreakers,
  fetchCircuitBreakers,
  getTelemetry,
  fetchTelemetry,
  fetchDeadLetterLogs,
  fetchDlqStats,
  getDlqStats,
  retryDeadLetterMessage,
  purgeDeadLetterMessage,
  login,
  register
};

export default api;
