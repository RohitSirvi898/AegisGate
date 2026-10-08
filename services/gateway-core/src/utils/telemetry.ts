import { AUDIT_EXCHANGE, AUDIT_ROUTING_KEY, getRabbitChannel } from '../config/queue.js';

export interface TelemetryEvent {
  requestId: string;
  timestamp: string;
  projectId?: string | undefined;
  apiKeyId?: string | undefined;
  clientIp: string;
  method: string;
  path: string;
  statusCode: number;
  rule?: string | undefined;
  errorCode?: string | undefined;
  upstreamOrigin?: string | undefined;
  headers?: Record<string, string> | Record<string, any> | undefined;
  query?: Record<string, any> | string | undefined;
  rawBody?: string | undefined;
  attackVector?: string | undefined;
  summary?: string | undefined;
  [key: string]: any;
}

export const TELEMETRY_BUFFER_MAX = Number(process.env.TELEMETRY_BUFFER_MAX) || 1000;
export const TELEMETRY_BODY_MAX_BYTES = Number(process.env.TELEMETRY_BODY_MAX_BYTES) || 2048;

const ALLOWED_HEADERS = new Set<string>([
  'host',
  'user-agent',
  'content-type',
  'content-length',
  'referer'
]);

const SENSITIVE_KEY_REGEX = /^(password|passwd|secret|token|api_?key|authorization|credit_?card|card_?number|cvv|ssn|email)$/i;
const SENSITIVE_QUERY_REGEX = /(password|passwd|secret|token|api_?key|auth|authorization)/i;

const SSN_REGEX = /\b\d{3}-\d{2}-\d{4}\b/g;
const EMAIL_REGEX = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/gi;
const POTENTIAL_CARD_REGEX = /\b(?:\d[ -]*?){13,19}\b/g;

export let telemetry_dropped_total = 0;

const eventBuffer: TelemetryEvent[] = [];

export function isLuhnValid(numberStr: string): boolean {
  const clean = numberStr.replace(/[\s-]/g, '');
  if (clean.length < 13 || clean.length > 19 || !/^\d+$/.test(clean)) {
    return false;
  }
  let sum = 0;
  let shouldDouble = false;
  for (let i = clean.length - 1; i >= 0; i--) {
    let digit = parseInt(clean.charAt(i), 10);
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

export function sanitizeHeaders(headers?: Record<string, any>): Record<string, string> {
  if (!headers) return {};
  const sanitized: Record<string, string> = {};

  for (const [key, value] of Object.entries(headers)) {
    const lowerKey = key.toLowerCase();
    if (ALLOWED_HEADERS.has(lowerKey) && value !== undefined && value !== null) {
      sanitized[lowerKey] = Array.isArray(value) ? value.join(', ') : String(value);
    }
  }

  return sanitized;
}

export function sanitizeQuery(query?: Record<string, any> | string): Record<string, any> | string | undefined {
  if (!query) return undefined;

  if (typeof query === 'string') {
    return query.replace(/([?&])([^=]+)=([^&]*)/g, (_match, prefix, key, value) => {
      if (SENSITIVE_QUERY_REGEX.test(key)) {
        return `${prefix}${key}=[REDACTED]`;
      }
      return `${prefix}${key}=${value}`;
    });
  }

  if (typeof query === 'object') {
    const sanitized: Record<string, any> = {};
    for (const [k, v] of Object.entries(query)) {
      if (SENSITIVE_QUERY_REGEX.test(k)) {
        sanitized[k] = '[REDACTED]';
      } else {
        sanitized[k] = v;
      }
    }
    return sanitized;
  }

  return query;
}

export function redactJsonRecursive(data: any): any {
  if (data === null || data === undefined) {
    return data;
  }

  if (Array.isArray(data)) {
    return data.map(item => redactJsonRecursive(item));
  }

  if (typeof data === 'object') {
    const result: Record<string, any> = {};
    for (const [key, val] of Object.entries(data)) {
      if (SENSITIVE_KEY_REGEX.test(key)) {
        result[key] = '[REDACTED]';
      } else {
        result[key] = redactJsonRecursive(val);
      }
    }
    return result;
  }

  return data;
}

export function maskPatternPii(text: string): string {
  let result = text;

  result = result.replace(SSN_REGEX, '[REDACTED_SSN]');
  result = result.replace(EMAIL_REGEX, '[REDACTED_EMAIL]');

  result = result.replace(POTENTIAL_CARD_REGEX, (match) => {
    if (isLuhnValid(match)) {
      return '[REDACTED_CARD]';
    }
    return match;
  });

  return result;
}

export function sanitizeBody(body?: any): string | undefined {
  if (body === undefined || body === null) {
    return undefined;
  }

  let bodyStr: string;
  if (typeof body === 'string') {
    bodyStr = body;
  } else {
    try {
      bodyStr = JSON.stringify(body);
    } catch {
      bodyStr = String(body);
    }
  }

  let cleaned = bodyStr;
  const trimmed = bodyStr.trim();
  if ((trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
    try {
      const parsed = JSON.parse(bodyStr);
      const scrubbedJson = redactJsonRecursive(parsed);
      cleaned = JSON.stringify(scrubbedJson);
    } catch {
      // Fall through to pattern masking
    }
  }

  cleaned = maskPatternPii(cleaned);

  if (Buffer.byteLength(cleaned, 'utf8') > TELEMETRY_BODY_MAX_BYTES) {
    cleaned = cleaned.slice(0, TELEMETRY_BODY_MAX_BYTES) + '...[TRUNCATED]';
  }

  return cleaned;
}

export function sanitizeTelemetryEvent(event: TelemetryEvent): TelemetryEvent {
  return {
    ...event,
    headers: sanitizeHeaders(event.headers),
    query: sanitizeQuery(event.query),
    rawBody: sanitizeBody(event.rawBody)
  };
}

let isDraining = false;

export async function drainTelemetryBuffer(): Promise<void> {
  if (isDraining) return;
  isDraining = true;

  try {
    const chan = getRabbitChannel();
    if (!chan) {
      return;
    }

    while (eventBuffer.length > 0) {
      const item = eventBuffer[0]!;
      const messageBuffer = Buffer.from(JSON.stringify(item));
      const published = chan.publish(AUDIT_EXCHANGE, AUDIT_ROUTING_KEY, messageBuffer, {
        persistent: true
      });

      if (published) {
        eventBuffer.shift();
      } else {
        break;
      }
    }
  } catch {
    // Retain events in buffer on drain error
  } finally {
    isDraining = false;
  }
}

export function recordTelemetryEvent(event: TelemetryEvent): void {
  const sanitized = sanitizeTelemetryEvent(event);

  // Bounded buffer eviction: drops oldest event when capacity reached to prioritize recent telemetry
  if (eventBuffer.length >= TELEMETRY_BUFFER_MAX) {
    eventBuffer.shift();
    telemetry_dropped_total++;
  }

  eventBuffer.push(sanitized);

  setImmediate(() => {
    drainTelemetryBuffer().catch(() => {});
  });
}

export function getTelemetryDroppedTotal(): number {
  return telemetry_dropped_total;
}

export function getTelemetryBufferSize(): number {
  return eventBuffer.length;
}

export function clearTelemetryBuffer(): void {
  eventBuffer.length = 0;
  telemetry_dropped_total = 0;
}
