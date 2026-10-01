import amqplib from 'amqplib';
import { sanitizePayload } from '../utils/piiScrubber.js';

const RABBITMQ_URL = process.env.RABBITMQ_URL || 'amqp://localhost:5672';
export const AUDIT_EXCHANGE = 'aegis_security_bus';
export const AUDIT_QUEUE = 'aegis.audit';
export const AUDIT_ROUTING_KEY = 'aegis.telemetry';

export const DLX_EXCHANGE = 'aegis_dlx';
export const DLX_QUEUE = 'aegis.audit.dlq';
export const DLX_ROUTING_KEY = 'dead_letter';

export const AUDIT_QUEUE_MAX_LENGTH = Number(process.env.AUDIT_QUEUE_MAX_LENGTH) || 100000;

let connection: amqplib.ChannelModel | null = null;
let channel: amqplib.Channel | null = null;

// In-memory queue to safely buffer telemetry payloads if RabbitMQ is offline or connecting
const pendingMessages: Array<object> = [];

export function getRabbitChannel(): amqplib.Channel | null {
    return channel;
}

export function getRabbitConnection(): amqplib.ChannelModel | null {
    return connection;
}

/**
 * Robust, self-healing recursive connection function that automatically retries
 * connection to RabbitMQ with a 5-second backoff.
 * Configures Dead-Letter Exchange (DLX) and bounded queue with drop-head overflow.
 */
export const connectRabbitMQ = async (): Promise<void> => {
    try {
        const conn = await amqplib.connect(RABBITMQ_URL);
        connection = conn;

        const chan = await conn.createChannel();
        channel = chan;

        // Assert TOPIC exchange named 'aegis_security_bus'
        await chan.assertExchange(AUDIT_EXCHANGE, 'topic', { durable: true });

        // Assert Dead-Letter Exchange (DLX) and DLQ
        await chan.assertExchange(DLX_EXCHANGE, 'direct', { durable: true });
        await chan.assertQueue(DLX_QUEUE, { durable: true });
        await chan.bindQueue(DLX_QUEUE, DLX_EXCHANGE, DLX_ROUTING_KEY);

        // Assert durable queue 'aegis.audit' with x-max-length, drop-head and DLX
        await chan.assertQueue(AUDIT_QUEUE, {
            durable: true,
            arguments: {
                'x-max-length': AUDIT_QUEUE_MAX_LENGTH,
                'x-overflow': 'drop-head',
                'x-dead-letter-exchange': DLX_EXCHANGE,
                'x-dead-letter-routing-key': DLX_ROUTING_KEY
            }
        });
        await chan.bindQueue(AUDIT_QUEUE, AUDIT_EXCHANGE, AUDIT_ROUTING_KEY);
        await chan.bindQueue(AUDIT_QUEUE, AUDIT_EXCHANGE, 'threat.blocked');

        // Backwards compatibility queue for legacy threat listeners
        await chan.assertQueue('blocked_threats_queue', {
            durable: true,
            arguments: {
                'x-dead-letter-exchange': DLX_EXCHANGE,
                'x-dead-letter-routing-key': DLX_ROUTING_KEY
            }
        });
        await chan.bindQueue('blocked_threats_queue', AUDIT_EXCHANGE, 'threat.blocked');

        console.log('🐇 [Aegis Message Bus] Successfully connected to RabbitMQ (aegis.audit queue active with DLX)!');

        conn.on('error', (err) => {
            console.error('🐇 [Aegis Message Bus Error] Connection error encountered:', err.message);
            handleReconnection();
        });

        conn.on('close', () => {
            console.warn('🐇 [Aegis Message Bus Notice] Connection closed. Triggering reconnection...');
            handleReconnection();
        });

        // Drain any pending telemetry logs cached while RabbitMQ was offline
        await drainPendingMessages();
    } catch (error: any) {
        console.warn('[Aegis Message Bus] RabbitMQ not ready yet. Retrying in 5 seconds...');
        setTimeout(() => connectRabbitMQ(), 5000);
    }
};

/**
 * Triggers self-healing reconnection cycle.
 */
const handleReconnection = (): void => {
    connection = null;
    channel = null;
    setTimeout(() => {
        connectRabbitMQ();
    }, 5000);
};

/**
 * Initializes the RabbitMQ connection, asserts the exchange/queues, and binds them.
 */
export const initQueue = async (): Promise<void> => {
    connectRabbitMQ().catch((error) => {
        console.error('🐇 [Aegis Message Bus Boot Failure] Critical startup exception:', error.message);
    });
};

/**
 * Drains the in-memory cache of pending telemetry logs.
 */
const drainPendingMessages = async (): Promise<void> => {
    if (!channel || pendingMessages.length === 0) return;

    console.log(`🐇 [Aegis Message Bus] Draining ${pendingMessages.length} pending threat logs from cache...`);
    const messagesToProcess = [...pendingMessages];
    pendingMessages.length = 0;

    for (const payload of messagesToProcess) {
        try {
            await publishThreatLog(payload);
        } catch (error: any) {
            console.error('🐇 [Aegis Message Bus Cache Drain Error] Failed to publish pending log:', error.message);
            pendingMessages.push(payload);
        }
    }
};

/**
 * Publishes a security threat payload to the 'aegis_security_bus' exchange.
 * Fail-Open policy: catches all issues and queues into in-memory buffer if broker is down.
 */
export const publishThreatLog = async (payload: object): Promise<void> => {
    try {
        const sanitizedPayload = sanitizePayload(payload);
        const chan = channel;
        if (!chan) {
            pendingMessages.push(sanitizedPayload);
            return;
        }

        const messageBuffer = Buffer.from(JSON.stringify(sanitizedPayload));
        const published = chan.publish(AUDIT_EXCHANGE, 'threat.blocked', messageBuffer, {
            persistent: true
        });

        if (!published) {
            pendingMessages.push(sanitizedPayload);
        }
    } catch (error: any) {
        pendingMessages.push(payload);
    }
};
