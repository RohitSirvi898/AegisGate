import amqplib from 'amqplib';
import { sanitizePayload } from '../utils/piiScrubber.js';

const RABBITMQ_URL = process.env.RABBITMQ_URL || 'amqp://localhost:5672';
const EXCHANGE_NAME = 'aegis_security_bus';
const QUEUE_NAME = 'blocked_threats_queue';
const ROUTING_KEY = 'threat.blocked';

const DLX_EXCHANGE = 'aegis_dlx';
const DLX_QUEUE = 'aegis_dead_letter';
const DLX_ROUTING_KEY = 'dead_letter';

let connection: amqplib.ChannelModel | null = null;
let channel: amqplib.Channel | null = null;

// In-memory queue to safely buffer telemetry payloads if RabbitMQ is offline or connecting
const pendingMessages: Array<object> = [];

/**
 * Robust, self-healing recursive connection function that automatically retries
 * connection to RabbitMQ with a 5-second backoff.
 * Configures Dead-Letter Exchange (DLX) for poison-message handling.
 */
export const connectRabbitMQ = async (): Promise<void> => {
    try {
        const conn = await amqplib.connect(RABBITMQ_URL);
        connection = conn;
        
        const chan = await conn.createChannel();
        channel = chan;

        // Assert a TOPIC exchange named 'aegis_security_bus'
        await chan.assertExchange(EXCHANGE_NAME, 'topic', {
            durable: true
        });

        // Assert Dead-Letter Exchange (DLX) and Dead-Letter Queue
        await chan.assertExchange(DLX_EXCHANGE, 'direct', { durable: true });
        await chan.assertQueue(DLX_QUEUE, { durable: true });
        await chan.bindQueue(DLX_QUEUE, DLX_EXCHANGE, DLX_ROUTING_KEY);

        // Assert durable queue with DLX routing options
        await chan.assertQueue(QUEUE_NAME, {
            durable: true,
            arguments: {
                'x-dead-letter-exchange': DLX_EXCHANGE,
                'x-dead-letter-routing-key': DLX_ROUTING_KEY
            }
        });

        // Bind the queue to the exchange using the routing key 'threat.blocked'
        await chan.bindQueue(QUEUE_NAME, EXCHANGE_NAME, ROUTING_KEY);

        console.log('🐇 [Aegis Message Bus] Successfully connected to RabbitMQ and initialized channel with DLX!');

        // Set up connection event handlers to trigger self-healing reconnect on failure
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
    pendingMessages.length = 0; // Clear the cache before sending to prevent loops

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
 * Designed with a Fail-Open policy: catches all connection/broker issues and continues cleanly.
 * Automatically sanitizes PII in payload before queueing.
 */
export const publishThreatLog = async (payload: object): Promise<void> => {
    try {
        const sanitizedPayload = sanitizePayload(payload);
        const chan = channel;
        if (!chan) {
            console.warn('[Queue Publisher Delay] RabbitMQ channel is not ready. Safely caching threat log payload...');
            pendingMessages.push(sanitizedPayload);
            return;
        }

        const messageBuffer = Buffer.from(JSON.stringify(sanitizedPayload));
        const published = chan.publish(EXCHANGE_NAME, ROUTING_KEY, messageBuffer, {
            persistent: true
        });

        if (!published) {
            console.warn('[Queue Publisher Warning] Channel publish buffer full or message not accepted. Caching log payload...');
            pendingMessages.push(sanitizedPayload);
        }
    } catch (error: any) {
        console.warn('[Queue Publisher Failure - Continuing Gateway Lifecycle] Caching payload due to:', error.message);
        pendingMessages.push(payload);
    }
};
