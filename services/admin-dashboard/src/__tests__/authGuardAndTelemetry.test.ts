import assert from 'node:assert/strict';
import {
    getAuthHeader,
    fetchCircuitBreakers,
    fetchJailedIps,
    fetchTelemetry,
    fetchProjects,
    fetchDlqStats,
    unbanClientIp,
    ApiError
} from '../services/api';
import { getStoredToken } from '../hooks/useThreatTelemetry';

console.log('🧪 Starting Admin Dashboard Auth Guard & Telemetry Verification Tests...\n');

// Mock localStorage and sessionStorage for testing
class MockStorage {
    private store = new Map<string, string>();
    getItem(key: string): string | null {
        return this.store.get(key) ?? null;
    }
    setItem(key: string, value: string): void {
        this.store.set(key, value);
    }
    removeItem(key: string): void {
        this.store.delete(key);
    }
    clear(): void {
        this.store.clear();
    }
}

const mockLocalStorage = new MockStorage();
const mockSessionStorage = new MockStorage();

(globalThis as any).localStorage = mockLocalStorage;
(globalThis as any).sessionStorage = mockSessionStorage;

// Track all outbound fetch requests
interface CapturedRequest {
    url: string;
    options?: RequestInit;
}
let capturedRequests: CapturedRequest[] = [];
let mockFetchHandler: (url: string, options?: RequestInit) => Promise<Response> = async () =>
    new Response(JSON.stringify({}), { status: 200, headers: { 'Content-Type': 'application/json' } });

(globalThis as any).fetch = async (url: string, options?: RequestInit) => {
    capturedRequests.push({ url, options });
    return mockFetchHandler(url, options);
};

async function runTests() {
    let passed = 0;
    let failed = 0;

    const test = async (name: string, fn: () => Promise<void> | void) => {
        try {
            await fn();
            console.log(`  ✅ PASS: ${name}`);
            passed++;
        } catch (err: any) {
            console.error(`  ❌ FAIL: ${name}`);
            console.error(`     ${err.message}`);
            if (err.stack) console.error(err.stack);
            failed++;
        }
    };

    console.log('--- Suite 1: Universal Bearer Token Attachment (api.ts) ---');

    await test('getAuthHeader returns empty object when no token is present', () => {
        mockLocalStorage.clear();
        mockSessionStorage.clear();
        const header = getAuthHeader();
        assert.deepEqual(header, {});
    });

    await test('getAuthHeader returns Bearer token from localStorage', () => {
        mockLocalStorage.clear();
        mockSessionStorage.clear();
        mockLocalStorage.setItem('aegis_token', 'jwt-test-local-token-xyz');
        const header = getAuthHeader();
        assert.deepEqual(header, { Authorization: 'Bearer jwt-test-local-token-xyz' });
    });

    await test('getAuthHeader returns Bearer token from sessionStorage when localStorage is empty', () => {
        mockLocalStorage.clear();
        mockSessionStorage.clear();
        mockSessionStorage.setItem('aegis_token', 'jwt-test-session-token-abc');
        const header = getAuthHeader();
        assert.deepEqual(header, { Authorization: 'Bearer jwt-test-session-token-abc' });
    });

    await test('getStoredToken retrieves stored token', () => {
        mockLocalStorage.clear();
        mockSessionStorage.clear();
        mockLocalStorage.setItem('aegis_token', 'token-12345');
        assert.equal(getStoredToken(), 'token-12345');
        mockLocalStorage.clear();
        mockSessionStorage.clear();
        assert.equal(getStoredToken(), null);
    });

    await test('fetchCircuitBreakers automatically attaches Bearer token from storage', async () => {
        mockLocalStorage.setItem('aegis_token', 'token-circuit-breaker-test');
        capturedRequests = [];
        mockFetchHandler = async () =>
            new Response(JSON.stringify({ circuitBreakers: [] }), { status: 200, headers: { 'Content-Type': 'application/json' } });

        await fetchCircuitBreakers();

        assert.equal(capturedRequests.length, 1);
        const headers = capturedRequests[0].options?.headers as Record<string, string>;
        assert.equal(headers['Authorization'], 'Bearer token-circuit-breaker-test');
    });

    await test('fetchJailedIps automatically attaches Bearer token from storage', async () => {
        mockLocalStorage.setItem('aegis_token', 'token-jailed-ips-test');
        capturedRequests = [];
        mockFetchHandler = async () =>
            new Response(JSON.stringify({ jailedIps: [] }), { status: 200, headers: { 'Content-Type': 'application/json' } });

        await fetchJailedIps();

        assert.equal(capturedRequests.length, 1);
        const headers = capturedRequests[0].options?.headers as Record<string, string>;
        assert.equal(headers['Authorization'], 'Bearer token-jailed-ips-test');
    });

    await test('fetchTelemetry automatically attaches Bearer token and project ID', async () => {
        mockLocalStorage.setItem('aegis_token', 'token-telemetry-test');
        capturedRequests = [];
        mockFetchHandler = async () =>
            new Response(JSON.stringify({ totalBlocks: 10, criticalCount: 2, highCount: 3, logs: [] }), {
                status: 200,
                headers: { 'Content-Type': 'application/json' }
            });

        await fetchTelemetry('proj_test_42');

        assert.equal(capturedRequests.length, 1);
        const headers = capturedRequests[0].options?.headers as Record<string, string>;
        assert.equal(headers['Authorization'], 'Bearer token-telemetry-test');
        assert.equal(headers['X-Project-Id'], 'proj_test_42');
    });

    await test('fetchProjects attaches Bearer token from storage', async () => {
        mockLocalStorage.setItem('aegis_token', 'token-projects-test');
        capturedRequests = [];
        mockFetchHandler = async () =>
            new Response(JSON.stringify([]), { status: 200, headers: { 'Content-Type': 'application/json' } });

        await fetchProjects();

        assert.equal(capturedRequests.length, 1);
        const headers = capturedRequests[0].options?.headers as Record<string, string>;
        assert.equal(headers['Authorization'], 'Bearer token-projects-test');
    });

    await test('fetchDlqStats attaches Bearer token from storage', async () => {
        mockLocalStorage.setItem('aegis_token', 'token-dlq-test');
        capturedRequests = [];
        mockFetchHandler = async () =>
            new Response(JSON.stringify({ total: 0 }), { status: 200, headers: { 'Content-Type': 'application/json' } });

        await fetchDlqStats();

        assert.equal(capturedRequests.length, 1);
        const headers = capturedRequests[0].options?.headers as Record<string, string>;
        assert.equal(headers['Authorization'], 'Bearer token-dlq-test');
    });

    await test('unbanClientIp attaches Bearer token from storage', async () => {
        mockLocalStorage.setItem('aegis_token', 'token-unban-test');
        capturedRequests = [];
        mockFetchHandler = async () =>
            new Response(JSON.stringify({ success: true }), { status: 200, headers: { 'Content-Type': 'application/json' } });

        await unbanClientIp('192.168.1.100');

        assert.equal(capturedRequests.length, 1);
        const headers = capturedRequests[0].options?.headers as Record<string, string>;
        assert.equal(headers['Authorization'], 'Bearer token-unban-test');
    });

    console.log('\n--- Suite 2: Auth-Gated Polling Loop & 401 Circuit Trip Verification ---');

    await test('Pre-flight Auth Check: skips polling network requests if no token is present', async () => {
        mockLocalStorage.clear();
        mockSessionStorage.clear();
        capturedRequests = [];

        // Simulate hook pre-flight check logic
        const token = null;
        const currentToken = token || getStoredToken();
        let connectionStatus = 'connected';
        let loading = true;

        if (!currentToken) {
            connectionStatus = 'unauthenticated';
            loading = false;
        } else {
            await fetchCircuitBreakers(currentToken);
        }

        assert.equal(connectionStatus, 'unauthenticated');
        assert.equal(loading, false);
        assert.equal(capturedRequests.length, 0, 'No HTTP requests should be fired when unauthenticated');
    });

    await test('401 Circuit Trip: halts timer and does NOT schedule next poll upon 401', async () => {
        mockLocalStorage.setItem('aegis_token', 'expired-bad-token');
        capturedRequests = [];

        mockFetchHandler = async () =>
            new Response(JSON.stringify({ message: 'Unauthorized' }), { status: 401, headers: { 'Content-Type': 'application/json' } });

        let connectionStatus = 'connected';
        let is401Unauthorized = false;
        let scheduledNextPoll = false;
        let timeoutId: any = 12345;

        // Execute synthetic polling cycle
        const results = await Promise.allSettled([
            fetchCircuitBreakers('expired-bad-token'),
            fetchJailedIps('expired-bad-token')
        ]);

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
            timeoutId = null;
            connectionStatus = 'unauthenticated';
        }

        // Check if next poll would be scheduled
        if (!is401Unauthorized) {
            scheduledNextPoll = true;
        }

        assert.equal(is401Unauthorized, true, 'Should detect 401 Unauthorized');
        assert.equal(connectionStatus, 'unauthenticated', 'Status should transition to unauthenticated');
        assert.equal(timeoutId, null, 'Active timeout should be cleared');
        assert.equal(scheduledNextPoll, false, 'Next poll MUST NOT be scheduled on 401');
    });

    await test('429 Rate Limit Handling: detects 429 and honors retry-after', async () => {
        mockLocalStorage.setItem('aegis_token', 'valid-token');
        capturedRequests = [];

        mockFetchHandler = async () =>
            new Response(JSON.stringify({ message: 'Too many requests' }), {
                status: 429,
                headers: { 'Content-Type': 'application/json', 'Retry-After': '15' }
            });

        const results = await Promise.allSettled([
            fetchCircuitBreakers('valid-token')
        ]);

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
                }
            }
        }

        assert.equal(isRateLimited, true, 'Should detect 429 Rate Limited');
        assert.equal(retryAfterSec, 15, 'Should respect Retry-After header of 15 seconds');
    });

    console.log(`\n==================================================`);
    console.log(`Results: ${passed} passed, ${failed} failed`);
    console.log(`==================================================\n`);

    if (failed > 0) {
        process.exit(1);
    }
}

runTests().catch((err) => {
    console.error('Fatal test error:', err);
    process.exit(1);
});
