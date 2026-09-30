import dotenv from 'dotenv';
import mongoose from 'mongoose';
import amqplib from 'amqplib';
import { ThreatLogModel } from './models/threatLog.js';
import { DeadLetterModel } from './models/deadLetter.js';
import { sendWebhookAlerts } from './utils/webhookNotifier.js';
import { sanitizePayload } from './utils/piiScrubber.js';

dotenv.config();

const MONGO_URI = process.env.MONGO_URI || '';
const RABBITMQ_URL = process.env.RABBITMQ_URL || 'amqp://localhost:5672';

const QUEUE_NAME = 'blocked_threats_queue';
const DLX_EXCHANGE = 'aegis_dlx';
const DLX_QUEUE = 'aegis_dead_letter';
const DLX_ROUTING_KEY = 'dead_letter';

let connection: amqplib.ChannelModel | null = null;
let channel: amqplib.Channel | null = null;

// In-memory batching buffer
let messageBuffer: { msg: amqplib.ConsumeMessage; payload: any }[] = [];
let lastFlushTime = Date.now();

/**
 * Extracts retry count from RabbitMQ x-death header.
 */
const getRetryCount = (msg: amqplib.ConsumeMessage): number => {
    const xDeath = msg.properties.headers?.['x-death'];
    if (Array.isArray(xDeath) && xDeath.length > 0) {
        return Number(xDeath[0].count) || xDeath.length;
    }
    return 0;
};

/**
 * Flushes batched threat payloads to MongoDB Atlas.
 * Applies local PII redaction engine on payloads.
 * Triggers Slack & Discord webhook alerts for CRITICAL/HIGH threats.
 * Routes poison messages to aegis_dead_letter DLQ on repeated failures.
 */
export const flushBuffer = async (): Promise<void> => {
    if (messageBuffer.length === 0) {
        return;
    }

    // Atomic snapshot and reset of the buffer
    const batch = [...messageBuffer];
    messageBuffer = [];
    lastFlushTime = Date.now();

    console.log(`⚡ [Buffer Flush] Initiating processing flush for batch of ${batch.length} threat logs.`);

    try {
        const dbDocs: any[] = [];
        const notificationQueue: any[] = [];

        for (const item of batch) {
            const rawBody = item.payload.rawBody ? sanitizePayload(item.payload.rawBody) : '';
            const attackVector = item.payload.attackVector || 'Security Filter Violation';
            const severity = item.payload.severity || 'HIGH';
            const summary = item.payload.summary || `Blocked threat pattern: ${attackVector}`;

            const doc = {
                projectId: item.payload.projectId || 'aegis_default_project',
                clientIp: item.payload.clientIp || 'unknown',
                endpoint: item.payload.endpoint || '',
                method: item.payload.method || 'POST',
                timestamp: item.payload.timestamp ? new Date(item.payload.timestamp) : new Date(),
                rawBody: typeof rawBody === 'string' ? rawBody : JSON.stringify(rawBody),
                attackVector,
                severity,
                summary,
                createdAt: new Date()
            };

            dbDocs.push(doc);

            if (item.payload.slackWebhookUrl || item.payload.discordWebhookUrl) {
                notificationQueue.push({
                    ...doc,
                    timestamp: item.payload.timestamp || new Date().toISOString(),
                    slackWebhookUrl: item.payload.slackWebhookUrl,
                    discordWebhookUrl: item.payload.discordWebhookUrl
                });
            }
        }

        // Persist all scrubbed threat records to MongoDB in a bulk write / insert
        if (dbDocs.length > 0) {
            await ThreatLogModel.insertMany(dbDocs);
            console.log(`💾 [Database] Successfully wrote ${dbDocs.length} telemetry records to MongoDB.`);
        }

        // Dispatch Slack & Discord webhook alerts asynchronously
        for (const notif of notificationQueue) {
            sendWebhookAlerts(notif).catch((err) => {
                console.error('[Webhook Dispatch Silent Catch]:', err?.message || err);
            });
        }

        // Acknowledge all processed messages from RabbitMQ
        for (const item of batch) {
            channel?.ack(item.msg);
        }
        console.log(`🐇 [Queue] Acknowledged ${batch.length} threat logs in RabbitMQ.`);
    } catch (error: any) {
        console.error('[Worker Analytics Fault - Inspecting Poison Message Retry Limits]');
        console.error('Error Trace:', error.message || error);

        // Fail-Closed Poison Message Routing via RabbitMQ DLX
        for (const item of batch) {
            try {
                const retryCount = getRetryCount(item.msg);
                if (retryCount < 3) {
                    console.warn(`🐇 [Queue Requeue] Message retry attempt ${retryCount + 1}/3. Requeueing...`);
                    channel?.nack(item.msg, false, true);
                } else {
                    console.error(`☠️ [Poison Message Detected] Exceeded ${retryCount} retries. Routing to aegis_dead_letter DLQ.`);
                    
                    // Persist poison message payload into DeadLetter collection for DLQ monitoring UI
                    await DeadLetterModel.create({
                        projectId: item.payload?.projectId || 'aegis_default_project',
                        clientIp: item.payload?.clientIp || 'unknown',
                        endpoint: item.payload?.endpoint || '',
                        method: item.payload?.method || 'POST',
                        timestamp: item.payload?.timestamp ? new Date(item.payload.timestamp) : new Date(),
                        rawBody: item.payload?.rawBody || JSON.stringify(item.payload || {}),
                        errorReason: error?.message || 'Exceeded maximum retries (3/3)',
                        retryCount: retryCount || 3
                    }).catch((dlErr) => console.error('[DeadLetter Store Exception]:', dlErr.message));

                    // Reject without requeueing -> RabbitMQ routes to aegis_dlx -> aegis_dead_letter DLQ
                    channel?.nack(item.msg, false, false);
                }
            } catch (nackError: any) {
                console.error('🐇 [Queue Nack Failure] Failed to release message:', nackError.message);
            }
        }
    }
};

/**
 * Boots the daemon worker process.
 */
export const startWorker = async (): Promise<void> => {
    try {
        console.log('🔌 Connecting to MongoDB...');
        await mongoose.connect(MONGO_URI);
        console.log('💾 Connected to MongoDB successfully.');

        console.log('🔌 Connecting to RabbitMQ...');
        connection = await amqplib.connect(RABBITMQ_URL);
        channel = await connection.createChannel();

        // Declare Dead-Letter Exchange & Queue
        await channel.assertExchange(DLX_EXCHANGE, 'direct', { durable: true });
        await channel.assertQueue(DLX_QUEUE, { durable: true });
        await channel.bindQueue(DLX_QUEUE, DLX_EXCHANGE, DLX_ROUTING_KEY);

        // Assert main queue with DLX routing arguments
        await channel.assertQueue(QUEUE_NAME, {
            durable: true,
            arguments: {
                'x-dead-letter-exchange': DLX_EXCHANGE,
                'x-dead-letter-routing-key': DLX_ROUTING_KEY
            }
        });

        await channel.prefetch(20);

        console.log('🐇 Connected to RabbitMQ successfully. DLX engaged. Prefetch set to 20.');

        setInterval(async () => {
            if (messageBuffer.length > 0 && Date.now() - lastFlushTime >= 30000) {
                console.log('⏱️ [Timer Flush] 30 seconds rolling timer elapsed. Flushing buffer...');
                await flushBuffer();
            }
        }, 1000);

        console.log('📥 Start consuming messages from blocked_threats_queue...');

        await channel.consume(
            QUEUE_NAME,
            async (msg) => {
                if (!msg) return;

                try {
                    const payload = JSON.parse(msg.content.toString());
                    messageBuffer.push({ msg, payload });

                    console.log(`📥 Received threat log. Buffer status: ${messageBuffer.length}/10`);

                    if (messageBuffer.length >= 10) {
                        console.log('🚀 [Capacity Flush] Buffer reached 10 records. Triggering flush...');
                        await flushBuffer();
                    }
                } catch (err: any) {
                    console.error('❌ [Consume Error] Malformed message rejected:', err.message);

                    // Persist malformed message into DeadLetter model for UI inspection
                    await DeadLetterModel.create({
                        projectId: 'aegis_default_project',
                        clientIp: 'unknown',
                        endpoint: '/malformed-payload',
                        method: 'POST',
                        timestamp: new Date(),
                        rawBody: msg.content.toString(),
                        errorReason: `Malformed JSON payload: ${err.message}`,
                        retryCount: 3
                    }).catch((dlErr) => console.error('[DeadLetter Store Exception]:', dlErr.message));

                    // Immediately nack without requeuing so malformed JSON goes straight to DLQ
                    channel?.nack(msg, false, false);
                }
            },
            { noAck: false }
        );

        console.log('🛡️ AegisGate Control Plane Background Worker is fully online.');
    } catch (error: any) {
        console.error('❌ [Worker Initialization Failure] Severe boot failure:', error.message);
        process.exit(1);
    }
};
