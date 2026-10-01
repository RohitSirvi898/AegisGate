import assert from 'node:assert/strict';
import { redisClient } from '../config/redis.js';
import { getClientIp, truncateIpv6To64, isIpInCidr, normalizeClientIp } from '../utils/ip.js';
import { validateTargetUrl, isPrivateOrReservedIp } from '../utils/ssrf.js';
import {
    checkCircuitAndBulkhead,
    extractOrigin,
    getOrCreateCircuitBreaker,
    recordUpstreamFailure,
    recordUpstreamSuccess,
    resetAllCircuitBreakers,
    BREAKER_FAILURE_THRESHOLD,
    MAX_INFLIGHT_PER_UPSTREAM
} from '../middleware/circuitBreaker.js';
import { sendGatewayError, DEFAULT_STATUS_CODES } from '../utils/errors.js';
import {
    normalizePath,
    buildCacheKey,
    createResponseCacheMiddleware
} from '../middleware/responseCache.js';
import {
    sanitizeHeaders,
    sanitizeQuery,
    sanitizeBody,
    isLuhnValid,
    recordTelemetryEvent,
    getTelemetryBufferSize,
    getTelemetryDroppedTotal,
    clearTelemetryBuffer,
    TELEMETRY_BUFFER_MAX
} from '../utils/telemetry.js';

console.log('🧪 Starting AegisGate PRD v2.1 Hardening Tests...\n');

// Mock ServerResponse
class MockServerResponse {
    statusCode = 200;
    headers: Record<string, string> = {};
    headersSent = false;
    body = '';

    setHeader(name: string, value: string) {
        this.headers[name.toLowerCase()] = value;
    }
    getHeader(name: string) {
        return this.headers[name.toLowerCase()];
    }
    writeHead(status: number, headers?: Record<string, string>) {
        this.statusCode = status;
        if (headers) {
            for (const [k, v] of Object.entries(headers)) {
                this.headers[k.toLowerCase()] = v;
            }
        }
        this.headersSent = true;
    }
    end(data?: any) {
        if (data) this.body = typeof data === 'string' ? data : Buffer.from(data).toString('utf8');
        return this;
    }
    write(data?: any) {
        if (data) this.body += typeof data === 'string' ? data : Buffer.from(data).toString('utf8');
        return true;
    }
    status(code: number) {
        this.statusCode = code;
        return this;
    }
    send(data: any) {
        this.body = typeof data === 'string' ? data : JSON.stringify(data);
        return this;
    }
    json(data: any) {
        this.headers['content-type'] = 'application/json';
        this.body = JSON.stringify(data);
        return this;
    }
}

// =========================================================================
// TEST 1: ERROR CONTRACT & REQUEST ID
// =========================================================================
console.log('--- TEST 1: Error Contract & Request ID ---');

assert.equal(DEFAULT_STATUS_CODES['invalid_or_missing_credentials'], 401);
assert.equal(DEFAULT_STATUS_CODES['ip_jailed'], 403);
assert.equal(DEFAULT_STATUS_CODES['request_blocked'], 403);
assert.equal(DEFAULT_STATUS_CODES['payload_too_large'], 413);
assert.equal(DEFAULT_STATUS_CODES['rate_limited'], 429);
assert.equal(DEFAULT_STATUS_CODES['upstream_unavailable'], 503);
assert.equal(DEFAULT_STATUS_CODES['upstream_saturated'], 503);
assert.equal(DEFAULT_STATUS_CODES['auth_backend_unavailable'], 503);
assert.equal(DEFAULT_STATUS_CODES['upstream_timeout'], 504);

const mockRes = new MockServerResponse();
const mockReq: any = { headers: {} };
sendGatewayError(mockRes as any, 429, 'rate_limited', mockReq, { retryAfterSeconds: 60 });

assert.equal(mockRes.statusCode, 429);
assert.ok(mockRes.headers['x-request-id']);
assert.equal(mockRes.headers['retry-after'], '60');
const parsedBody = JSON.parse(mockRes.body);
assert.equal(parsedBody.error, 'rate_limited');
assert.equal(parsedBody.requestId, mockRes.headers['x-request-id']);

console.log('✅ Error contract and Request ID tests passed!');

// =========================================================================
// TEST 2: CLIENT IP DERIVATION & NORMALIZATION
// =========================================================================
console.log('\n--- TEST 2: Client IP Derivation & Normalization ---');

assert.equal(normalizeClientIp('::ffff:192.168.1.5'), '192.168.1.5');
assert.equal(normalizeClientIp('::FFFF:127.0.0.1'), '127.0.0.1');

const ipv6_1 = '2001:db8:abcd:0012:0000:0000:0000:0001';
const ipv6_2 = '2001:db8:abcd:0012:ffff:eeee:dddd:cccc';
const trunc1 = truncateIpv6To64(ipv6_1);
const trunc2 = truncateIpv6To64(ipv6_2);
assert.equal(trunc1, '2001:db8:abcd:12::/64');
assert.equal(trunc2, '2001:db8:abcd:12::/64');
assert.equal(trunc1, trunc2, 'Both IPs in same /64 must resolve to identical key');

assert.ok(isIpInCidr('10.0.5.23', '10.0.0.0/8'));
assert.ok(isIpInCidr('192.168.1.100', '192.168.0.0/16'));
assert.ok(isIpInCidr('127.0.0.1', '127.0.0.0/8'));
assert.ok(!isIpInCidr('8.8.8.8', '10.0.0.0/8'));

process.env.TRUSTED_PROXY_CIDRS = '10.0.0.0/8, 127.0.0.1/32';

const trustedReq: any = {
    socket: { remoteAddress: '10.0.0.2' },
    headers: {
        'x-forwarded-for': '203.0.113.195, 10.0.0.15'
    }
};
const resolvedIp = getClientIp(trustedReq);
assert.equal(resolvedIp, '203.0.113.195', 'Must walk right-to-left skipping trusted proxies');

const untrustedReq: any = {
    socket: { remoteAddress: '198.51.100.5' },
    headers: {
        'x-forwarded-for': '1.1.1.1, 10.0.0.1'
    }
};
const untrustedResolved = getClientIp(untrustedReq);
assert.equal(untrustedResolved, '198.51.100.5', 'Untrusted peer must strictly fallback to socket address');

console.log('✅ Client IP derivation, normalization, and trusted proxy tests passed!');

// =========================================================================
// TEST 3: CONNECT-TIME SSRF PROTECTION
// =========================================================================
console.log('\n--- TEST 3: Connect-Time SSRF Protection ---');

delete process.env.ALLOW_PRIVATE_UPSTREAMS;

assert.ok(validateTargetUrl('http://api.example.com/v1').valid);
assert.ok(validateTargetUrl('https://secure.example.com:8443/data').valid);

assert.ok(!validateTargetUrl('ftp://example.com').valid);
assert.ok(!validateTargetUrl('file:///etc/passwd').valid);
assert.ok(!validateTargetUrl('http://admin:secret@api.example.com').valid);

assert.ok(!validateTargetUrl('http://api.example.com:22').valid);
assert.ok(!validateTargetUrl('http://api.example.com:6379').valid);
assert.ok(!validateTargetUrl('http://api.example.com:27017').valid);
assert.ok(!validateTargetUrl('http://api.example.com:5432').valid);
assert.ok(!validateTargetUrl('http://api.example.com:5672').valid);
assert.ok(!validateTargetUrl('http://api.example.com:9200').valid);

assert.ok(!validateTargetUrl('http://127.0.0.1:8080').valid);
assert.ok(!validateTargetUrl('http://169.254.169.254/latest/meta-data/').valid);
assert.ok(!validateTargetUrl('http://10.0.0.1:3000').valid);
assert.ok(!validateTargetUrl('http://192.168.1.1/').valid);

assert.ok(isPrivateOrReservedIp('127.0.0.1'));
assert.ok(isPrivateOrReservedIp('169.254.169.254'));
assert.ok(isPrivateOrReservedIp('10.255.0.1'));
assert.ok(isPrivateOrReservedIp('172.16.0.1'));
assert.ok(isPrivateOrReservedIp('192.168.1.1'));
assert.ok(isPrivateOrReservedIp('100.64.0.1'));
assert.ok(isPrivateOrReservedIp('::1'));
assert.ok(isPrivateOrReservedIp('fc00::1'));
assert.ok(isPrivateOrReservedIp('fe80::1'));

assert.ok(!isPrivateOrReservedIp('93.184.216.34'));
assert.ok(!isPrivateOrReservedIp('8.8.8.8'));

console.log('✅ SSRF validation and IP denylist tests passed!');

// =========================================================================
// TEST 4: PER-UPSTREAM CIRCUIT BREAKER & BULKHEAD
// =========================================================================
console.log('\n--- TEST 4: Per-Upstream Circuit Breaker & Bulkhead ---');

resetAllCircuitBreakers();

const testOrigin = 'https://upstream-service.internal:8443';
assert.equal(extractOrigin('https://upstream-service.internal:8443/api/v1?query=1'), testOrigin);

const breaker = getOrCreateCircuitBreaker(testOrigin);
assert.equal(breaker.state, 'CLOSED');
assert.equal(breaker.consecutiveFailures, 0);

const check1 = checkCircuitAndBulkhead(testOrigin);
assert.equal(check1.allowed, true);

breaker.inFlight = MAX_INFLIGHT_PER_UPSTREAM;
const bulkheadCheck = checkCircuitAndBulkhead(testOrigin);
assert.equal(bulkheadCheck.allowed, false);
assert.equal((bulkheadCheck as any).reason, 'upstream_saturated');
breaker.inFlight = 0;

for (let i = 0; i < BREAKER_FAILURE_THRESHOLD; i++) {
    recordUpstreamFailure(testOrigin);
}
assert.equal(breaker.state, 'OPEN');

const openCheck = checkCircuitAndBulkhead(testOrigin);
assert.equal(openCheck.allowed, false);
assert.equal((openCheck as any).reason, 'upstream_unavailable');

breaker.lastStateChange = Date.now() - 31000;
const halfOpenCheck = checkCircuitAndBulkhead(testOrigin);
assert.equal(breaker.state, 'HALF_OPEN');
assert.equal(breaker.probeInFlight, true);
assert.equal(halfOpenCheck.allowed, false);
assert.equal((halfOpenCheck as any).reason, 'upstream_unavailable');

recordUpstreamSuccess(testOrigin);
assert.equal(breaker.state, 'CLOSED');
assert.equal(breaker.consecutiveFailures, 0);

console.log('✅ Circuit breaker and Bulkhead tests passed!');

// =========================================================================
// TEST 5: SAFE GET RESPONSE CACHING (PRD v2.1 Section 4.7)
// =========================================================================
console.log('\n--- TEST 5: Safe GET Response Caching ---');

// 5.1 Normalized and sorted query param cache key matching
const key1 = buildCacheKey('proj1', 'route1', '/api/v1/products', { b: '2', a: '1' }, ['a', 'b']);
const key2 = buildCacheKey('proj1', 'route1', '/api/v1/products', { a: '1', b: '2' }, ['a', 'b']);
assert.ok(key1 !== null);
assert.equal(key1, key2, '?b=2&a=1 must generate identical cache key as ?a=1&b=2');
assert.equal(key1, 'cache:proj1:route1:GET:/api/v1/products?a=1&b=2');

// 5.2 Path normalization & dot segment removal
assert.equal(normalizePath('/api/v1/../v1/products/./'), '/api/v1/products');
assert.equal(normalizePath('/api//v1///products'), '/api/v1/products');
assert.equal(normalizePath('/api/v1%2fproducts'), null, 'Encoded slashes must bypass cache (return null)');

// 5.3 Key length > 512 bytes bypasses cache
const giantParam = 'x'.repeat(550);
const oversizeKey = buildCacheKey('proj1', 'route1', '/path', { q: giantParam }, ['q']);
assert.equal(oversizeKey, null, 'Keys longer than 512 bytes must return null');

// 5.4 Cache middleware eligibility: Bypass on Authorization or Cookie
const cacheMw = createResponseCacheMiddleware(() => ({
    enabled: true,
    ttlSec: 60,
    allowedQueryParams: ['page', 'limit']
}));

const authReq: any = {
    method: 'GET',
    path: '/api/v1/products',
    headers: { authorization: 'Bearer token123' },
    query: { page: '1' }
};
const authRes = new MockServerResponse();
let nextCalled = false;
await cacheMw(authReq, authRes as any, () => { nextCalled = true; });
assert.ok(nextCalled);
assert.equal(authRes.headers['x-aegis-cache'], 'BYPASS', 'Requests with Authorization header must BYPASS cache');

const cookieReq: any = {
    method: 'GET',
    path: '/api/v1/products',
    headers: { cookie: 'session_id=abc' },
    query: { page: '1' }
};
const cookieRes = new MockServerResponse();
nextCalled = false;
await cacheMw(cookieReq, cookieRes as any, () => { nextCalled = true; });
assert.ok(nextCalled);
assert.equal(cookieRes.headers['x-aegis-cache'], 'BYPASS', 'Requests with Cookie header must BYPASS cache');

// 5.5 Cache middleware eligibility: Bypass on unlisted query parameter
const unlistedReq: any = {
    method: 'GET',
    path: '/api/v1/products',
    headers: {},
    query: { page: '1', cacheBuster: 'random123' } // cacheBuster is unlisted
};
const unlistedRes = new MockServerResponse();
nextCalled = false;
await cacheMw(unlistedReq, unlistedRes as any, () => { nextCalled = true; });
assert.ok(nextCalled);
assert.equal(unlistedRes.headers['x-aegis-cache'], 'BYPASS', 'Requests with unlisted query params must BYPASS cache');

console.log('✅ Response caching eligibility and key generation tests passed!');

// =========================================================================
// TEST 6: PRE-QUEUE PII REDACTION & BOUNDED BUFFER (PRD Section 4.11)
// =========================================================================
console.log('\n--- TEST 6: Pre-Queue PII Redaction & Bounded Buffer ---');

// 6.1 Header allowlist
const rawHeaders = {
    'Host': 'api.aegisgate.io',
    'User-Agent': 'Mozilla/5.0',
    'Content-Type': 'application/json',
    'Authorization': 'Bearer super_secret_jwt',
    'Cookie': 'auth_token=12345',
    'X-Aegis-Api-Key': 'ag_secret_key_999',
    'X-Custom-Header': 'forbidden'
};
const scrubbedHeaders = sanitizeHeaders(rawHeaders);
assert.equal(scrubbedHeaders['host'], 'api.aegisgate.io');
assert.equal(scrubbedHeaders['user-agent'], 'Mozilla/5.0');
assert.equal(scrubbedHeaders['content-type'], 'application/json');
assert.equal(scrubbedHeaders['authorization'], undefined, 'Authorization header must be stripped');
assert.equal(scrubbedHeaders['cookie'], undefined, 'Cookie header must be stripped');
assert.equal(scrubbedHeaders['x-aegis-api-key'], undefined, 'X-Aegis-Api-Key must be stripped');
assert.equal(scrubbedHeaders['x-custom-header'], undefined, 'Non-whitelisted headers must be stripped');

// 6.2 Sensitive query parameter redaction
const queryObj = { user: 'rohit', password: 'myPassword123', token: 'xyz987', page: '2' };
const sanitizedQuery = sanitizeQuery(queryObj) as Record<string, any>;
assert.equal(sanitizedQuery['user'], 'rohit');
assert.equal(sanitizedQuery['page'], '2');
assert.equal(sanitizedQuery['password'], '[REDACTED]');
assert.equal(sanitizedQuery['token'], '[REDACTED]');

// 6.3 Luhn credit card validation check
assert.ok(isLuhnValid('4111111111111111'), 'Valid Visa number must pass Luhn');
assert.ok(!isLuhnValid('4111111111111112'), 'Invalid number must fail Luhn');

// 6.4 Body sanitization: JSON key redaction + pattern masking
const sensitiveJson = {
    user: 'alice',
    password: 'superSecretPassword',
    apiKey: 'key_123456789',
    ssn: '123-45-6789',
    email: 'alice@example.com',
    details: {
        credit_card: '4111-1111-1111-1111',
        token: 'token_abc'
    }
};
const sanitizedJsonStr = sanitizeBody(sensitiveJson)!;
assert.ok(!sanitizedJsonStr.includes('superSecretPassword'));
assert.ok(!sanitizedJsonStr.includes('key_123456789'));
assert.ok(!sanitizedJsonStr.includes('123-45-6789'));
assert.ok(!sanitizedJsonStr.includes('alice@example.com'));
assert.ok(!sanitizedJsonStr.includes('4111-1111-1111-1111'));
assert.ok(sanitizedJsonStr.includes('[REDACTED]'));

// 6.5 Free text body masking
const rawText = 'Contact bob@corp.com with SSN 000-12-3456 and Card 4111111111111111';
const sanitizedText = sanitizeBody(rawText)!;
assert.ok(!sanitizedText.includes('bob@corp.com'));
assert.ok(!sanitizedText.includes('000-12-3456'));
assert.ok(!sanitizedText.includes('4111111111111111'));
assert.ok(sanitizedText.includes('[REDACTED_EMAIL]'));
assert.ok(sanitizedText.includes('[REDACTED_SSN]'));
assert.ok(sanitizedText.includes('[REDACTED_CARD]'));

// 6.6 Bounded buffer with DROP-OLDEST policy
clearTelemetryBuffer();
assert.equal(getTelemetryBufferSize(), 0);
assert.equal(getTelemetryDroppedTotal(), 0);

// Push TELEMETRY_BUFFER_MAX + 5 events
for (let i = 0; i < TELEMETRY_BUFFER_MAX + 5; i++) {
    recordTelemetryEvent({
        requestId: `req-${i}`,
        timestamp: new Date().toISOString(),
        clientIp: '127.0.0.1',
        method: 'GET',
        path: `/test-${i}`,
        statusCode: 200
    });
}

assert.equal(getTelemetryBufferSize(), TELEMETRY_BUFFER_MAX, 'Buffer size must be capped at 1,000');
assert.equal(getTelemetryDroppedTotal(), 5, 'Exactly 5 oldest events must be dropped');

console.log('✅ Pre-queue telemetry redaction and bounded buffer tests passed!');

console.log('\n🎉 ALL PRD v2.1 HARDENING TESTS PASSED SUCCESSFULLY! 🎉\n');

redisClient.disconnect(false);
process.exit(0);
