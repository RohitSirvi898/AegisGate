const SENSITIVE_KEYS = [
    'password',
    'pass',
    'token',
    'auth',
    'authorization',
    'secret',
    'credit_card',
    'ssn',
    'cvv',
    'api_key'
];

/**
 * Regex for masking sensitive key-value pairs in raw text or stringified JSON payloads.
 */
const SENSITIVE_STRING_REGEX = new RegExp(
    `(["']?(?:${SENSITIVE_KEYS.join('|')})["']?\\s*[:=]\\s*)(["']?)(?:[^\\s,"'\\}]+)\\2`,
    'gi'
);

/**
 * Pattern-based regex masks for emails, 16-digit credit cards, and US SSNs.
 */
const EMAIL_REGEX = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/gi;
const CARD_REGEX = /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g;
const SSN_REGEX = /\b\d{3}-\d{2}-\d{4}\b/g;

/**
 * Checks if an object key matches any sensitive key definitions.
 */
const isSensitiveKey = (key: string): boolean => {
    const lowerKey = key.toLowerCase();
    return SENSITIVE_KEYS.some((sensitive) => lowerKey === sensitive || lowerKey.includes(sensitive));
};

/**
 * Recursively inspects JSON objects, arrays, and stringified payloads, replacing
 * sensitive keys and pattern-matched PII (Email, Card, SSN) with redaction masks.
 */
export function sanitizePayload(data: any): any {
    if (data === null || data === undefined) {
        return data;
    }

    if (typeof data === 'string') {
        const trimmed = data.trim();
        // Check if string is a stringified JSON object or array
        if ((trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
            try {
                const parsed = JSON.parse(data);
                const sanitized = sanitizePayload(parsed);
                let stringified = JSON.stringify(sanitized);
                // Apply pattern masks across stringified output
                stringified = stringified.replace(SSN_REGEX, '[REDACTED_SSN]');
                stringified = stringified.replace(CARD_REGEX, '[REDACTED_CARD]');
                stringified = stringified.replace(EMAIL_REGEX, '[REDACTED_EMAIL]');
                return stringified;
            } catch {
                // Fall back to string regex masking if JSON parse fails
            }
        }

        let result = data;
        result = result.replace(SSN_REGEX, '[REDACTED_SSN]');
        result = result.replace(CARD_REGEX, '[REDACTED_CARD]');
        result = result.replace(EMAIL_REGEX, '[REDACTED_EMAIL]');
        result = result.replace(SENSITIVE_STRING_REGEX, '$1"[REDACTED]"');

        return result;
    }

    if (Array.isArray(data)) {
        return data.map((item) => sanitizePayload(item));
    }

    if (typeof data === 'object') {
        const sanitizedObj: Record<string, any> = {};
        for (const [key, value] of Object.entries(data)) {
            if (isSensitiveKey(key)) {
                sanitizedObj[key] = '[REDACTED]';
            } else {
                sanitizedObj[key] = sanitizePayload(value);
            }
        }
        return sanitizedObj;
    }

    return data;
}
