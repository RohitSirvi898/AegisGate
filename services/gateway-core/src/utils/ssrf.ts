import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';

import { cleanIpString, isIpInCidrList } from './ip.js';

// Rejects private subnets (RFC 1918/3927) and cloud metadata services (169.254.169.254)
export const IPV4_DENYLIST: string[] = [
  '0.0.0.0/8',
  '10.0.0.0/8',
  '100.64.0.0/10',
  '127.0.0.0/8',
  '169.254.0.0/16',
  '172.16.0.0/12',
  '192.168.0.0/16',
  '224.0.0.0/4',
  '240.0.0.0/4'
];

export const IPV6_DENYLIST: string[] = [
  '::/128',
  '::1/128',
  'fc00::/7',
  'fe80::/10',
  'ff00::/8',
  '::ffff:0:0/96'
];

export const DANGEROUS_PORTS = new Set<number>([
  20, 21,
  22,
  23,
  25,
  53,
  69,
  110, 143,
  161, 162,
  389, 636,
  2375, 2376,
  2379, 2380,
  3306,
  5432,
  5672,
  6379,
  8500,
  9200, 9300,
  11211,
  15672,
  27017, 27018, 27019,
  28017
]);

export function isPrivateOrReservedIp(ipStr: string): boolean {
  const clean = cleanIpString(ipStr);

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

  return true;
}

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

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return {
      valid: false,
      reason: `Invalid protocol '${parsed.protocol}'. Only 'http:' and 'https:' are permitted.`
    };
  }

  if (parsed.username !== '' || parsed.password !== '') {
    return {
      valid: false,
      reason: 'URL credentials (user:pass) are strictly forbidden for upstream targets.'
    };
  }

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

// Pins verified IP to socket connection to prevent DNS rebinding (TOCTOU) attacks
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

  const ipFamily = net.isIP(hostname);
  if (ipFamily !== 0) {
    if (!allowPrivate && isPrivateOrReservedIp(hostname)) {
      const err: any = new Error(`SSRF Blocked: Connection to private or reserved IP (${hostname}) denied.`);
      err.code = 'ERR_SSRF_DENIED';
      return callback(err, '', 0);
    }
    return callback(null, hostname, ipFamily);
  }

  dns.lookup(hostname, { all: true }, (err, addresses) => {
    if (err) {
      return callback(err, '', 0);
    }

    if (!addresses || addresses.length === 0) {
      const noAddrErr: any = new Error(`DNS Resolution Failure: No address found for host '${hostname}'.`);
      noAddrErr.code = 'ENOTFOUND';
      return callback(noAddrErr, '', 0);
    }

    for (const entry of addresses) {
      if (!allowPrivate && isPrivateOrReservedIp(entry.address)) {
        const ssrfErr: any = new Error(
          `SSRF Blocked: Host '${hostname}' resolved to forbidden private/reserved IP (${entry.address}).`
        );
        ssrfErr.code = 'ERR_SSRF_DENIED';
        return callback(ssrfErr, '', 0);
      }
    }

    const chosen = addresses[0]!;
    if (options && options.all) {
      return callback(null, addresses as any);
    }
    return callback(null, chosen.address, chosen.family);
  });
}

export function createSsrfSafeHttpAgent(options?: http.AgentOptions): http.Agent {
  return new http.Agent({
    keepAlive: true,
    maxSockets: 100,
    lookup: ssrfSafeLookup,
    ...options
  });
}

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

export function getSsrfSafeAgent(targetUrl?: string): http.Agent | https.Agent {
  if (targetUrl && targetUrl.startsWith('https:')) {
    return ssrfHttpsAgent;
  }
  return ssrfHttpAgent;
}
