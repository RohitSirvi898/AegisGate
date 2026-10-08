import net from 'node:net';

import type { Request } from 'express';

export function cleanIpString(rawIp: string): string {
  let clean = rawIp.trim();

  if (clean.startsWith('[')) {
    const closeIdx = clean.indexOf(']');
    if (closeIdx !== -1) {
      clean = clean.slice(1, closeIdx);
    }
  } else if (clean.includes('.') && clean.includes(':')) {
    if (!clean.startsWith('::ffff:') && !clean.startsWith('::FFFF:')) {
      const lastColon = clean.lastIndexOf(':');
      const portPart = clean.slice(lastColon + 1);
      if (/^\d+$/.test(portPart)) {
        clean = clean.slice(0, lastColon);
      }
    }
  }

  const ipv4MappedMatch = clean.match(/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i);
  if (ipv4MappedMatch && ipv4MappedMatch[1]) {
    return ipv4MappedMatch[1];
  }

  return clean;
}

export function parseIpv4(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;

  let num = 0;
  for (let i = 0; i < 4; i++) {
    const part = parts[i];
    if (!part || !/^\d+$/.test(part)) return null;
    const octet = parseInt(part, 10);
    if (octet < 0 || octet > 255) return null;
    num = (num << 8) | octet;
  }
  return num >>> 0;
}

export function parseIpv6(ipStr: string): number[] | null {
  let clean = cleanIpString(ipStr);

  if (clean.match(/^::ffff:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/i)) {
    return null;
  }

  if (clean.includes('::')) {
    const parts = clean.split('::');
    if (parts.length !== 2) return null;

    const leftStr = parts[0];
    const rightStr = parts[1];

    const leftHextets: number[] = [];
    if (leftStr && leftStr.length > 0) {
      for (const h of leftStr.split(':')) {
        if (!h || !/^[0-9a-fA-F]{1,4}$/.test(h)) return null;
        leftHextets.push(parseInt(h, 16));
      }
    }

    const rightHextets: number[] = [];
    if (rightStr && rightStr.length > 0) {
      for (const h of rightStr.split(':')) {
        if (!h || !/^[0-9a-fA-F]{1,4}$/.test(h)) return null;
        rightHextets.push(parseInt(h, 16));
      }
    }

    const missing = 8 - (leftHextets.length + rightHextets.length);
    if (missing < 1) return null;

    return [...leftHextets, ...new Array(missing).fill(0), ...rightHextets];
  } else {
    const hextets: number[] = [];
    for (const h of clean.split(':')) {
      if (!h || !/^[0-9a-fA-F]{1,4}$/.test(h)) return null;
      hextets.push(parseInt(h, 16));
    }
    if (hextets.length !== 8) return null;
    return hextets;
  }
}

// Truncates native IPv6 to /64 prefix to group subnet rotation into a unified identity
export function truncateIpv6To64(ip: string): string {
  const hextets = parseIpv6(ip);
  if (!hextets) {
    return ip;
  }

  const h0 = (hextets[0] ?? 0).toString(16);
  const h1 = (hextets[1] ?? 0).toString(16);
  const h2 = (hextets[2] ?? 0).toString(16);
  const h3 = (hextets[3] ?? 0).toString(16);

  return `${h0}:${h1}:${h2}:${h3}::/64`;
}

function ipv6ToBigInt(hextets: number[]): bigint {
  let result = 0n;
  for (const h of hextets) {
    result = (result << 16n) | BigInt(h);
  }
  return result;
}

function isIpv4InCidr(ipInt: number, cidrIpInt: number, prefixLen: number): boolean {
  if (prefixLen <= 0) return true;
  if (prefixLen > 32) return false;
  const mask = prefixLen === 32 ? 0xffffffff : (~((1 << (32 - prefixLen)) - 1)) >>> 0;
  return ((ipInt & mask) >>> 0) === ((cidrIpInt & mask) >>> 0);
}

function isIpv6InCidr(ipBigInt: bigint, cidrBigInt: bigint, prefixLen: number): boolean {
  if (prefixLen <= 0) return true;
  if (prefixLen > 128) return false;
  const shift = 128n - BigInt(prefixLen);
  const mask = ((1n << 128n) - 1n) ^ ((1n << shift) - 1n);
  return (ipBigInt & mask) === (cidrBigInt & mask);
}

export function isIpInCidr(ipStr: string, cidrStr: string): boolean {
  const cleanIp = cleanIpString(ipStr);
  const trimmedCidr = cidrStr.trim();

  const [cidrBase, prefixStr] = trimmedCidr.split('/');
  if (!cidrBase) return false;

  const cleanCidrBase = cleanIpString(cidrBase);

  const ipInt = parseIpv4(cleanIp);
  const cidrBaseInt = parseIpv4(cleanCidrBase);

  if (ipInt !== null && cidrBaseInt !== null) {
    const prefixLen = prefixStr !== undefined ? parseInt(prefixStr, 10) : 32;
    if (isNaN(prefixLen)) return false;
    return isIpv4InCidr(ipInt, cidrBaseInt, prefixLen);
  }

  const ipHextets = parseIpv6(cleanIp);
  const cidrHextets = parseIpv6(cleanCidrBase);

  if (ipHextets !== null && cidrHextets !== null) {
    const prefixLen = prefixStr !== undefined ? parseInt(prefixStr, 10) : 128;
    if (isNaN(prefixLen)) return false;
    return isIpv6InCidr(ipv6ToBigInt(ipHextets), ipv6ToBigInt(cidrHextets), prefixLen);
  }

  return false;
}

export function isIpInCidrList(ipStr: string, cidrs: string[]): boolean {
  for (const cidr of cidrs) {
    if (cidr.trim() && isIpInCidr(ipStr, cidr)) {
      return true;
    }
  }
  return false;
}

export function normalizeClientIp(ipStr: string): string {
  const clean = cleanIpString(ipStr);

  if (net.isIPv4(clean)) {
    return clean;
  }

  if (net.isIPv6(clean)) {
    return truncateIpv6To64(clean);
  }

  return clean;
}

export function getTrustedProxyCidrs(): string[] {
  const raw = process.env.TRUSTED_PROXY_CIDRS || '';
  return raw
    .split(',')
    .map(c => c.trim())
    .filter(c => c.length > 0);
}

export function getClientIp(req: Request): string {
  const rawSocketIp = req.socket?.remoteAddress || '127.0.0.1';
  const socketIp = cleanIpString(rawSocketIp);

  const trustedCidrs = getTrustedProxyCidrs();

  if (trustedCidrs.length === 0 || !isIpInCidrList(socketIp, trustedCidrs)) {
    return normalizeClientIp(socketIp);
  }

  const rawXff = req.headers['x-forwarded-for'];
  if (!rawXff) {
    return normalizeClientIp(socketIp);
  }

  const xffStr = Array.isArray(rawXff) ? rawXff.join(',') : rawXff;
  const parts = xffStr
    .split(',')
    .map(p => cleanIpString(p))
    .filter(p => p.length > 0);

  if (parts.length === 0) {
    return normalizeClientIp(socketIp);
  }

  for (let i = parts.length - 1; i >= 0; i--) {
    const candidate = parts[i]!;
    if (isIpInCidrList(candidate, trustedCidrs)) {
      continue;
    }
    return normalizeClientIp(candidate);
  }

  const leftmost = parts[0]!;
  return normalizeClientIp(leftmost);
}
