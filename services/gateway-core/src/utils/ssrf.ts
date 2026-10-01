import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns';
import net from 'node:net';
import { isIpInCidrList, cleanIpString } from './ip.js';

/**
 * Standard IPv4 Denylist for connect-time and registration-time SSRF guards.
 */
export const IPV4_DENYLIST: string[] = [
    '0.0.0.0/8',       // Current network (only valid as source)
    '10.0.0.0/8',      // Private-Use (RFC 1918)
    '100.64.0.0/10',   // Shared Address Space / Carrier-Grade NAT (RFC 6598)
    '127.0.0.0/8',     // Loopback (RFC 1122)
    '169.254.0.0/16',  // Link-Local / Cloud Provider Metadata APIs (e.g. AWS/GCP 169.254.169.254)
    '172.16.0.0/12',   // Private-Use (RFC 1918)
    '192.168.0.0/16',  // Private-Use (RFC 1918)
    '224.0.0.0/4',     // Multicast (RFC 5771)
    '240.0.0.0/4'      // Reserved for future use / broadcast (RFC 1112)
];

/**
 * Standard IPv6 Denylist for connect-time and registration-time SSRF guards.
 */
export const IPV6_DENYLIST: string[] = [
    '::/128',          // Unspecified address
    '::1/128',         // Loopback
    'fc00::/7',        // Unique Local Address (ULA, RFC 4193)
    'fe80::/10',       // Link-Local Unicast (RFC 4291)
    'ff00::/8',        // Multicast (RFC 4291)
    '::ffff:0:0/96'    // IPv4-mapped addresses
];

/**
 * Highly dangerous or internal infrastructure ports forbidden for proxy targets.
 */
export const DANGEROUS_PORTS = new Set<number>([
    20, 21,     // FTP
    22,         // SSH
    23,         // Telnet
    25,         // SMTP
    53,         // DNS
    69,         // TFTP
    110, 143,   // POP3, IMAP
    161, 162,   // SNMP
    389, 636,   // LDAP
    2375, 2376, // Docker daemon
    2379, 2380, // etcd
    3306,       // MySQL
    5432,       // PostgreSQL
    5672,       // RabbitMQ
    6379,       // Redis
    8500,       // Consul
    9200, 9300, // Elasticsearch
    11211,      // Memcached
    15672,      // RabbitMQ Management
    27017, 27018, 27019, // MongoDB
    28017       // MongoDB Web
]);

/**
 * Evaluates whether an IP address belongs to private, reserved, or loopback ranges.
 */
export function isPrivateOrReservedIp(ipStr: string): boolean {
    const clean = cleanIpString(ipStr);

    // Check for IPv4-mapped IPv6 (::ffff:a.b.c.d)
    const ipv4Mapped = clean.match(/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i);
    if (ipv4Mapped && ipv4Mapped[1]) {
        return isIpInCidrList(ipv4Mapped[1], IPV4_DENYLIST);
    }

    if (net.isIPv4(clean)) {
        return isIpInCidrList(clean, IPV4_DENYLIST);
    }

    if (net.isIPv6(clean)) {
        return isIpInCidrList(clean, IPV6_DENYLIST);
    }

    // Non-parseable or malformed IP string treated as untrusted
    return true;
}

/**
 * Registration-time and route-resolution SSRF validator:
 * 1. Enforces scheme 'http' or 'https' only.
 * 2. Rejects URLs with embedded credentials (user:pass@).
 * 3. Blocks dangerous infrastructure ports.
 * 4. Disallows direct private/reserved IP literals (unless ALLOW_PRIVATE_UPSTREAMS=true).
 */
export function validateTargetUrl(rawUrl: string): { valid: boolean; reason?: string } {
    if (!rawUrl || typeof rawUrl !== 'string') {
        return { valid: false, reason: 'Target URL is missing or empty' };
    }

    let parsed: URL;
    try {
        parsed = new URL(rawUrl);
    } catch {
        return { valid: false, reason: 'Target URL is malformed' };
    }

    // 1. Enforce http / https scheme only
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        return {
            valid: false,
            reason: `Invalid protocol '${parsed.protocol}'. Only 'http:' and 'https:' are permitted.`
        };
    }

    // 2. Reject credentials in URL
    if (parsed.username !== '' || parsed.password !== '') {
        return {
            valid: false,
            reason: 'URL credentials (user:pass) are strictly forbidden for upstream targets.'
        };
    }

    // 3. Block dangerous ports
    const port = parsed.port ? parseInt(parsed.port, 10) : (parsed.protocol === 'https:' ? 443 : 80);
    if (isNaN(port) || port <= 0 || port > 65535) {
        return { valid: false, reason: `Invalid port number: ${parsed.port}` };
    }

    if (DANGEROUS_PORTS.has(port)) {
        return {
            valid: false,
            reason: `Port ${port} is blocked for security reasons.`
        };
    }

    // 4. Check for direct private IP literal (if ALLOW_PRIVATE_UPSTREAMS is false)
    const allowPrivate = process.env.ALLOW_PRIVATE_UPSTREAMS === 'true';
    if (!allowPrivate && net.isIP(parsed.hostname) !== 0) {
        if (isPrivateOrReservedIp(parsed.hostname)) {
            return {
                valid: false,
                reason: `Target host '${parsed.hostname}' is a forbidden private or reserved IP address.`
            };
        }
    }

    return { valid: true };
}

/**
 * Connect-time DNS validation lookup function for Node.js http.Agent and https.Agent.
 * Resolves hostname to IP before establishing the socket and prevents DNS rebinding.
 */
export function ssrfSafeLookup(
    hostname: string,
    options: any,
    callback: (err: NodeJS.ErrnoException | null, address: any, family?: number) => void
): void {
    if (typeof options === 'function') {
        callback = options;
        options = {};
    }

    const allowPrivate = process.env.ALLOW_PRIVATE_UPSTREAMS === 'true';

    // Fast-path: Hostname is already an IP address
    const ipFamily = net.isIP(hostname);
    if (ipFamily !== 0) {
        if (!allowPrivate && isPrivateOrReservedIp(hostname)) {
            const err: any = new Error(`SSRF Blocked: Connection to private or reserved IP (${hostname}) denied.`);
            err.code = 'ERR_SSRF_DENIED';
            return callback(err, '', 0);
        }
        return callback(null, hostname, ipFamily);
    }

    // Perform DNS lookup
    dns.lookup(hostname, { all: true }, (err, addresses) => {
        if (err) {
            return callback(err, '', 0);
        }

        if (!addresses || addresses.length === 0) {
            const noAddrErr: any = new Error(`DNS Resolution Failure: No address found for host '${hostname}'.`);
            noAddrErr.code = 'ENOTFOUND';
            return callback(noAddrErr, '', 0);
        }

        // Verify that EVERY resolved IP address satisfies the denylist
        for (const entry of addresses) {
            if (!allowPrivate && isPrivateOrReservedIp(entry.address)) {
                const ssrfErr: any = new Error(
                    `SSRF Blocked: Host '${hostname}' resolved to forbidden private/reserved IP (${entry.address}).`
                );
                ssrfErr.code = 'ERR_SSRF_DENIED';
                return callback(ssrfErr, '', 0);
            }
        }

        // Pin the connection to the first verified IP address (eliminates DNS-rebinding attacks)
        const chosen = addresses[0]!;
        if (options && options.all) {
            return callback(null, addresses as any);
        }
        return callback(null, chosen.address, chosen.family);
    });
}

/**
 * Creates an SSRF-safe http.Agent with connection pooling and DNS pinning.
 */
export function createSsrfSafeHttpAgent(options?: http.AgentOptions): http.Agent {
    return new http.Agent({
        keepAlive: true,
        maxSockets: 100,
        lookup: ssrfSafeLookup,
        ...options
    });
}

/**
 * Creates an SSRF-safe https.Agent with connection pooling and DNS pinning.
 */
export function createSsrfSafeHttpsAgent(options?: https.AgentOptions): https.Agent {
    return new https.Agent({
        keepAlive: true,
        maxSockets: 100,
        lookup: ssrfSafeLookup,
        ...options
    });
}

export const ssrfHttpAgent = createSsrfSafeHttpAgent();
export const ssrfHttpsAgent = createSsrfSafeHttpsAgent();

/**
 * Returns the appropriate SSRF-safe connection agent for a given target URL.
 */
export function getSsrfSafeAgent(targetUrl?: string): http.Agent | https.Agent {
    if (targetUrl && targetUrl.startsWith('https:')) {
        return ssrfHttpsAgent;
    }
    return ssrfHttpAgent;
}
