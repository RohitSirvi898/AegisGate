import assert from 'node:assert/strict';
import { getClientIp, cleanIpString, truncateIpv6To64, isIpInCidr, normalizeClientIp } from '../utils/ip.js';
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
import { sendGatewayError, getOrSetRequestId, DEFAULT_STATUS_CODES } from '../utils/errors.js';
import { ServerResponse } from 'node:http';

console.log('🧪 Starting AegisGate PRD v2.1 Hardening Tests...\n');

// =========================================================================
// TEST 1: ERROR CONTRACT & REQUEST ID
// =========================================================================
console.log('--- TEST 1: Error Contract & Request ID ---');

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
    end(data?: string) {
        if (data) this.body = data;
    }
}

// 1.1 Verify default status codes
assert.equal(DEFAULT_STATUS_CODES['invalid_or_missing_credentials'], 401);
assert.equal(DEFAULT_STATUS_CODES['ip_jailed'], 403);
assert.equal(DEFAULT_STATUS_CODES['request_blocked'], 403);
assert.equal(DEFAULT_STATUS_CODES['payload_too_large'], 413);
assert.equal(DEFAULT_STATUS_CODES['rate_limited'], 429);
assert.equal(DEFAULT_STATUS_CODES['upstream_unavailable'], 503);
assert.equal(DEFAULT_STATUS_CODES['upstream_saturated'], 503);
assert.equal(DEFAULT_STATUS_CODES['auth_backend_unavailable'], 503);
assert.equal(DEFAULT_STATUS_CODES['upstream_timeout'], 504);

// 1.2 Verify sendGatewayError with MockServerResponse
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

// 2.1 IPv4 mapped normalization
assert.equal(normalizeClientIp('::ffff:192.168.1.5'), '192.168.1.5');
assert.equal(normalizeClientIp('::FFFF:127.0.0.1'), '127.0.0.1');

// 2.2 Native IPv6 truncation to /64
const ipv6_1 = '2001:db8:abcd:0012:0000:0000:0000:0001';
const ipv6_2 = '2001:db8:abcd:0012:ffff:eeee:dddd:cccc';
const trunc1 = truncateIpv6To64(ipv6_1);
const trunc2 = truncateIpv6To64(ipv6_2);
assert.equal(trunc1, '2001:db8:abcd:12::/64');
assert.equal(trunc2, '2001:db8:abcd:12::/64');
assert.equal(trunc1, trunc2, 'Both IPs in same /64 must resolve to identical key');

// 2.3 CIDR checking
assert.ok(isIpInCidr('10.0.5.23', '10.0.0.0/8'));
assert.ok(isIpInCidr('192.168.1.100', '192.168.0.0/16'));
assert.ok(isIpInCidr('127.0.0.1', '127.0.0.0/8'));
assert.ok(!isIpInCidr('8.8.8.8', '10.0.0.0/8'));

// 2.4 Trusted proxy parsing (walking right-to-left)
process.env.TRUSTED_PROXY_CIDRS = '10.0.0.0/8, 127.0.0.1/32';

// Peer is trusted proxy (10.0.0.2)
const trustedReq: any = {
    socket: { remoteAddress: '10.0.0.2' },
    headers: {
        'x-forwarded-for': '203.0.113.195, 10.0.0.15'
    }
};
const resolvedIp = getClientIp(trustedReq);
assert.equal(resolvedIp, '203.0.113.195', 'Must walk right-to-left skipping trusted proxies');

// Peer is untrusted direct client (198.51.100.5) trying to spoof XFF
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
// TEST 3: SSRF PROTECTION
// =========================================================================
console.log('\n--- TEST 3: Connect-Time SSRF Protection ---');

delete process.env.ALLOW_PRIVATE_UPSTREAMS;

// 3.1 validateTargetUrl checks
assert.ok(validateTargetUrl('http://api.example.com/v1').valid);
assert.ok(validateTargetUrl('https://secure.example.com:8443/data').valid);

// Forbidden protocols
assert.ok(!validateTargetUrl('ftp://example.com').valid);
assert.ok(!validateTargetUrl('file:///etc/passwd').valid);

// Forbidden credentials
assert.ok(!validateTargetUrl('http://admin:secret@api.example.com').valid);

// Forbidden dangerous ports
assert.ok(!validateTargetUrl('http://api.example.com:22').valid);    // SSH
assert.ok(!validateTargetUrl('http://api.example.com:6379').valid);  // Redis
assert.ok(!validateTargetUrl('http://api.example.com:27017').valid); // MongoDB
assert.ok(!validateTargetUrl('http://api.example.com:5432').valid);  // Postgres
assert.ok(!validateTargetUrl('http://api.example.com:5672').valid);  // RabbitMQ
assert.ok(!validateTargetUrl('http://api.example.com:9200').valid);  // Elastic

// Direct private IPs (when ALLOW_PRIVATE_UPSTREAMS is not true)
assert.ok(!validateTargetUrl('http://127.0.0.1:8080').valid);
assert.ok(!validateTargetUrl('http://169.254.169.254/latest/meta-data/').valid);
assert.ok(!validateTargetUrl('http://10.0.0.1:3000').valid);
assert.ok(!validateTargetUrl('http://192.168.1.1/').valid);

// 3.2 isPrivateOrReservedIp denylist check
assert.ok(isPrivateOrReservedIp('127.0.0.1'));
assert.ok(isPrivateOrReservedIp('169.254.169.254'));
assert.ok(isPrivateOrReservedIp('10.255.0.1'));
assert.ok(isPrivateOrReservedIp('172.16.0.1'));
assert.ok(isPrivateOrReservedIp('192.168.1.1'));
assert.ok(isPrivateOrReservedIp('100.64.0.1'));
assert.ok(isPrivateOrReservedIp('::1'));
assert.ok(isPrivateOrReservedIp('fc00::1'));
assert.ok(isPrivateOrReservedIp('fe80::1'));

// Public IPs must not be flagged
assert.ok(!isPrivateOrReservedIp('93.184.216.34')); // example.com
assert.ok(!isPrivateOrReservedIp('8.8.8.8'));        // Google DNS

console.log('✅ SSRF validation and IP denylist tests passed!');

// =========================================================================
// TEST 4: PER-UPSTREAM CIRCUIT BREAKER & BULKHEAD
// =========================================================================
console.log('\n--- TEST 4: Per-Upstream Circuit Breaker & Bulkhead ---');

resetAllCircuitBreakers();

const testOrigin = 'https://upstream-service.internal:8443';
assert.equal(extractOrigin('https://upstream-service.internal:8443/api/v1?query=1'), testOrigin);

// 4.1 Initial State should be CLOSED
const breaker = getOrCreateCircuitBreaker(testOrigin);
assert.equal(breaker.state, 'CLOSED');
assert.equal(breaker.consecutiveFailures, 0);

const check1 = checkCircuitAndBulkhead(testOrigin);
assert.equal(check1.allowed, true);

// 4.2 Bulkhead check: Exceed MAX_INFLIGHT_PER_UPSTREAM
breaker.inFlight = MAX_INFLIGHT_PER_UPSTREAM;
const bulkheadCheck = checkCircuitAndBulkhead(testOrigin);
assert.equal(bulkheadCheck.allowed, false);
assert.equal((bulkheadCheck as any).reason, 'upstream_saturated');
breaker.inFlight = 0; // reset

// 4.3 Trip circuit to OPEN on BREAKER_FAILURE_THRESHOLD (5) failures
for (let i = 0; i < BREAKER_FAILURE_THRESHOLD; i++) {
    recordUpstreamFailure(testOrigin);
}
assert.equal(breaker.state, 'OPEN');

const openCheck = checkCircuitAndBulkhead(testOrigin);
assert.equal(openCheck.allowed, false);
assert.equal((openCheck as any).reason, 'upstream_unavailable');

// 4.4 Cooldown transition to HALF_OPEN
// Simulate cooldown expired (31 seconds later)
breaker.lastStateChange = Date.now() - 31000;
const halfOpenCheck = checkCircuitAndBulkhead(testOrigin);
assert.equal(breaker.state, 'HALF_OPEN');
assert.equal(breaker.probeInFlight, true);
assert.equal(halfOpenCheck.allowed, false);
assert.equal((halfOpenCheck as any).reason, 'upstream_unavailable');

// 4.5 Success resets to CLOSED
recordUpstreamSuccess(testOrigin);
assert.equal(breaker.state, 'CLOSED');
assert.equal(breaker.consecutiveFailures, 0);

console.log('✅ Circuit breaker and Bulkhead tests passed!');

console.log('\n🎉 ALL PRD v2.1 HARDENING TESTS PASSED SUCCESSFULLY! 🎉\n');
