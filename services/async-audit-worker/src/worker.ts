import dotenv from 'dotenv';
import mongoose from 'mongoose';
import amqplib from 'amqplib';
import crypto from 'node:crypto';
import { AuditLogModel } from './models/AuditLog.js';
import { sendWebhookAlerts } from './utils/webhooks.js';

dotenv.config();

const MONGO_URI = process.env.MONGO_URI || '';
const RABBITMQ_URL = process.env.RABBITMQ_URL || 'amqp://localhost:5672';

export const AUDIT_QUEUE = 'aegis.audit';
export const DLX_EXCHANGE = 'aegis_dlx';
export const DLX_QUEUE = 'aegis.audit.dlq';
export const DLX_ROUTING_KEY = 'dead_letter';

// PRD v2.1 Section 4.11 Configuration Defaults
export const WORKER_BATCH_SIZE = Number(process.env.WORKER_BATCH_SIZE) || 20;
export const WORKER_BATCH_FLUSH_MS = Number(process.env.WORKER_BATCH_FLUSH_MS) || 500;
export const WORKER_PREFETCH = Number(process.env.WORKER_PREFETCH) || 50;

let connection: amqplib.ChannelModel | null = null;
let channel: amqplib.Channel | null = null;
let consumerTag: string | null = null;

// In-memory batch accumulation
interface BatchItem {
    msg: amqplib.ConsumeMessage;
    doc: any;
    payload: any;
}

let messageBatch: BatchItem[] = [];
let batchTimer: NodeJS.Timeout | null = null;
let isFlushing = false;

/**
 * Returns the current in-memory batch size (for testing/diagnostics).
 */
export function getBatchSize(): number {
    return messageBatch.length;
}

/**
 * Resets the in-memory batch buffer (for testing/diagnostics).
 */
export function resetBatch(): void {
    messageBatch = [];
    if (batchTimer) {
        clearTimeout(batchTimer);
        batchTimer = null;
    }
    isFlushing = false;
}

/**
 * Sets the active channel instance (useful for unit testing).
 */
export function setWorkerChannel(mockChannel: any): void {
    channel = mockChannel;
}

/**
 * Transforms an incoming message payload into a standardized AuditLog document.
 */
export function transformPayloadToDoc(payload: any): any {
    return {
        requestId: payload.requestId || crypto.randomUUID(),
        projectId: payload.projectId || 'aegis_default_project',
        apiKeyId: payload.apiKeyId || undefined,
        ip: payload.ip || payload.clientIp || '127.0.0.1',
        method: payload.method || 'GET',
        path: payload.path || payload.endpoint || '/',
        rule: payload.rule || payload.attackVector || undefined,
        status: payload.status ?? payload.statusCode ?? 200,
        upstreamOrigin: payload.upstreamOrigin || undefined,
        headers: payload.headers && typeof payload.headers === 'object' ? payload.headers : undefined,
        body: payload.body ?? payload.rawBody ?? undefined,
        createdAt: payload.timestamp ? new Date(payload.timestamp) : new Date()
    };
}

/**
 * Flushes the accumulated batch of messages into MongoDB using bulk insert.
 * Acknowledges all messages in batch upon success.
 * If MongoDB fails, pauses consumption and retries with exponential backoff.
 */
export async function flushBatch(): Promise<void> {
    if (messageBatch.length === 0 || isFlushing) {
        return;
    }

    if (batchTimer) {
        clearTimeout(batchTimer);
        batchTimer = null;
    }

    isFlushing = true;
    const currentBatch = [...messageBatch];
    messageBatch = [];

    try {
        const docs = currentBatch.map(item => item.doc);

        // Bulk insert into MongoDB with ordered: false for maximum throughput
        await AuditLogModel.insertMany(docs, { ordered: false });
        console.log(`💾 [MongoDB Bulk Insert] Successfully persisted ${docs.length} audit logs.`);

        // Acknowledge all messages in the batch up to and including the last message
        const lastMsg = currentBatch[currentBatch.length - 1]!.msg;
        channel?.ack(lastMsg, true);

        // Asynchronously dispatch webhook alerts for high-severity blocked requests
        for (const item of currentBatch) {
            if (item.doc.status === 403 || item.doc.rule === 'request_blocked') {
                sendWebhookAlerts({
                    projectId: item.doc.projectId,
                    clientIp: item.doc.ip,
                    path: item.doc.path,
                    method: item.doc.method,
                    status: item.doc.status,
                    rule: item.doc.rule,
                    summary: item.payload?.summary,
                    body: item.doc.body,
                    timestamp: item.doc.createdAt?.toISOString(),
                    slackWebhookUrl: item.payload?.slackWebhookUrl,
                    discordWebhookUrl: item.payload?.discordWebhookUrl
                }).catch(err => {
                    console.error('[Webhook Dispatch Silent Catch]:', err?.message || err);
                });
            }
        }
    } catch (dbErr: any) {
        console.error('❌ [MongoDB Batch Write Fault]:', dbErr?.message || dbErr);
        // Put unacknowledged messages into the outage handler
        await handleMongoOutage(currentBatch);
    } finally {
        isFlushing = false;
        // If messages arrived during flush and reached threshold, trigger immediate flush
        if (messageBatch.length >= WORKER_BATCH_SIZE) {
            setImmediate(() => {
                flushBatch().catch(() => {});
            });
        }
    }
}

/**
 * Handles MongoDB connectivity outage:
 * 1. Pauses RabbitMQ consumer (channel.cancel).
 * 2. Does NOT ack the batch (messages remain in RabbitMQ for redelivery).
 * 3. Retries with exponential backoff (1s, 2s, 4s, up to 30s max).
 * 4. Once reconnected, acks batch and resumes consumer.
 */
export async function handleMongoOutage(
    failedBatch: BatchItem[],
    initialBackoffMs = Number(process.env.DB_BACKOFF_INIT_MS) || 1000
): Promise<void> {
    // 1. Pause channel consumption so uncommitted messages don't pile up
    if (channel && consumerTag) {
        try {
            await channel.cancel(consumerTag);
            consumerTag = null;
            console.warn('⏸️ [Consumer Paused] Paused RabbitMQ consumption due to MongoDB failure.');
        } catch (err: any) {
            console.error('[Consumer Cancel Error]:', err?.message || err);
        }
    }

    // 2. Retry with exponential backoff
    let backoffMs = initialBackoffMs;
    const maxBackoffMs = 30000;
    let recovered = false;

    while (!recovered) {
        console.warn(`⏳ [DB Backoff] Retrying MongoDB write in ${backoffMs}ms...`);
        await new Promise(resolve => setTimeout(resolve, backoffMs));

        try {
            const docs = failedBatch.map(b => b.doc);
            await AuditLogModel.insertMany(docs, { ordered: false });
            recovered = true;
            console.log(`✅ [MongoDB Recovered] Persisted ${docs.length} audit logs after outage.`);

            // Acknowledge the batch now that MongoDB accepted the records
            const lastMsg = failedBatch[failedBatch.length - 1]!.msg;
            channel?.ack(lastMsg, true);

            // 3. Resume consumer
            await resumeConsumer();
        } catch (retryErr: any) {
            console.error('❌ [MongoDB Retry Failed]:', retryErr?.message || retryErr);
            backoffMs = Math.min(backoffMs * 2, maxBackoffMs);
        }
    }
}

/**
 * Resumes RabbitMQ message consumption once dependencies are healthy.
 */
export async function resumeConsumer(): Promise<void> {
    if (!channel || consumerTag) return;
    try {
        const consumeResult = await channel.consume(AUDIT_QUEUE, onMessage, { noAck: false });
        consumerTag = consumeResult.consumerTag;
        console.log(`▶️ [Consumer Resumed] Actively consuming from '${AUDIT_QUEUE}'.`);
    } catch (err: any) {
        console.error('❌ [Resume Consumer Error]:', err?.message || err);
    }
}

/**
 * Core message intake handler:
 * - Detects poison messages / invalid JSON and routes to DLQ (nack with requeue=false).
 * - Transforms payload into AuditLog schema.
 * - Flushes immediately when batch reaches 20, or schedules 500ms timeout flush.
 */
export async function onMessage(msg: amqplib.ConsumeMessage | null): Promise<void> {
    if (!msg) return;

    let payload: any;
    try {
        payload = JSON.parse(msg.content.toString());
    } catch (parseErr: any) {
        console.error('❌ [Poison Message - Bad JSON] Routing to DLQ:', parseErr.message);
        // Reject without requeueing -> RabbitMQ routes to aegis.audit.dlq via DLX
        channel?.nack(msg, false, false);
        return;
    }

    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
        console.error('❌ [Poison Message - Corrupt Schema] Routing to DLQ.');
        channel?.nack(msg, false, false);
        return;
    }

    const doc = transformPayloadToDoc(payload);
    messageBatch.push({ msg, doc, payload });

    // Condition 1: Batch size reached (WORKER_BATCH_SIZE = 20) -> Flush immediately
    if (messageBatch.length >= WORKER_BATCH_SIZE) {
        await flushBatch();
        return;
    }

    // Condition 2: 500ms elapsed since first message in batch -> Timer flush
    if (!batchTimer) {
        batchTimer = setTimeout(() => {
            batchTimer = null;
            flushBatch().catch(err => {
                console.error('[Scheduled Batch Flush Error]:', err?.message || err);
            });
        }, WORKER_BATCH_FLUSH_MS);
    }
}

/**
 * Boots the daemon worker process.
 */
export const startWorker = async (): Promise<void> => {
    try {
        console.log('🔌 Connecting to MongoDB Atlas...');
        await mongoose.connect(MONGO_URI);
        console.log('💾 Connected to MongoDB successfully.');

        console.log('🔌 Connecting to RabbitMQ Broker...');
        connection = await amqplib.connect(RABBITMQ_URL);
        channel = await connection.createChannel();

        // 1. Assert Dead-Letter Exchange (DLX) & Queue
        await channel.assertExchange(DLX_EXCHANGE, 'direct', { durable: true });
        await channel.assertQueue(DLX_QUEUE, { durable: true });
        await channel.bindQueue(DLX_QUEUE, DLX_EXCHANGE, DLX_ROUTING_KEY);

        // 2. Assert Durable 'aegis.audit' Queue with DLX & Drop-Head Overflow
        await channel.assertQueue(AUDIT_QUEUE, {
            durable: true,
            arguments: {
                'x-max-length': 100000,
                'x-overflow': 'drop-head',
                'x-dead-letter-exchange': DLX_EXCHANGE,
                'x-dead-letter-routing-key': DLX_ROUTING_KEY
            }
        });

        // 3. Set Channel Prefetch to 50 strictly per PRD Section 4.11
        await channel.prefetch(WORKER_PREFETCH);
        console.log(`🐇 RabbitMQ prefetch configured to ${WORKER_PREFETCH}.`);

        // 4. Start consuming from aegis.audit
        const consumeResult = await channel.consume(AUDIT_QUEUE, onMessage, { noAck: false });
        consumerTag = consumeResult.consumerTag;
        console.log(`📥 Subscribed to '${AUDIT_QUEUE}'. Batching at ${WORKER_BATCH_SIZE} msgs or ${WORKER_BATCH_FLUSH_MS}ms.`);

        // Also consume legacy queue if present for backward compatibility
        try {
            await channel.assertQueue('blocked_threats_queue', {
                durable: true,
                arguments: {
                    'x-dead-letter-exchange': DLX_EXCHANGE,
                    'x-dead-letter-routing-key': DLX_ROUTING_KEY
                }
            });
            await channel.consume('blocked_threats_queue', onMessage, { noAck: false });
        } catch {
            // Ignore if legacy queue is not needed
        }

        console.log('🛡️ AegisGate Async Audit Worker is fully online.');
    } catch (error: any) {
        console.error('❌ [Worker Boot Failure] Critical exception:', error?.message || error);
        process.exit(1);
    }
};
