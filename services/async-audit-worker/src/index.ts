import axios from 'axios';
import dotenv from 'dotenv';
import mongoose from 'mongoose';
import amqplib from 'amqplib';
import { ThreatLogModel } from './models/threatLog.js';

dotenv.config();

const PORT = process.env.PORT || '8081';
const MONGO_URI = process.env.MONGO_URI || '';
const RABBITMQ_URL = process.env.RABBITMQ_URL || 'amqp://localhost:5672';
const LLM_API_KEY = process.env.LLM_API_KEY || '';

const QUEUE_NAME = 'blocked_threats_queue';
const GEMINI_API_URL = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent';

let connection: amqplib.ChannelModel | null = null;
let channel: amqplib.Channel | null = null;

// In-memory batching buffer
let messageBuffer: { msg: amqplib.ConsumeMessage; payload: any }[] = [];
let lastFlushTime = Date.now();

/**
 * Triggers a processing flush, sending the batched threats to Gemini API for intelligence mapping
 * and writing them to MongoDB.
 */
const flushBuffer = async (): Promise<void> => {
    if (messageBuffer.length === 0) {
        return;
    }

    // Atomic snapshot and reset of the buffer to prevent race conditions or double processing
    const batch = [...messageBuffer];
    messageBuffer = [];
    lastFlushTime = Date.now();

    console.log(`⚡ [Buffer Flush] Initiating processing flush for batch of ${batch.length} threat logs.`);

    try {
        const threatItems = batch.map(item => item.payload);

        // Format threat logs into a highly readable structured string for LLM input
        const formattedThreats = threatItems.map((item, idx) => `
Record #${idx + 1}:
Client IP: ${item.clientIp}
Requested Endpoint: ${item.endpoint}
HTTP Method: ${item.method}
Timestamp: ${item.timestamp}
Request Payload: ${item.rawBody}
        `).join('\n---\n');

        const systemPrompt = `You are a Principal Security Intelligence Analyst. Analyze the following batch of blocked API threats.
STRICTLY respond with a valid JSON array of objects (one object per Record in the exact order presented), where each object contains exactly the following keys:
- 'attackVector' (string, e.g. "SQL Injection", "XSS", "Anomaly")
- 'severity' (string, e.g. "CRITICAL", "HIGH", "MEDIUM", "LOW")
- 'summary' (string, a concise human-readable security analysis summary)

Your response must be ONLY the raw JSON array. Do not include markdown code block backticks or other conversational text.`;

        console.log(`🤖 [LLM API Call] Requesting AI threat analysis from Gemini API...`);

        const response = await axios.post(
            `${GEMINI_API_URL}?key=${LLM_API_KEY}`,
            {
                contents: [{
                    parts: [{
                        text: `${systemPrompt}\n\nThreat Records:\n${formattedThreats}`
                    }]
                }],
                generationConfig: {
                    responseMimeType: "application/json"
                }
            },
            {
                headers: {
                    'Content-Type': 'application/json'
                },
                timeout: 25000 // 25s timeout for network safety
            }
        );

        const responseText = response.data?.candidates?.[0]?.content?.parts?.[0]?.text;
        if (!responseText) {
            throw new Error('Gemini API returned an empty or invalid response content.');
        }

        // Parse LLM generated intelligence data
        const cleanText = responseText.replace(/```json/g, '').replace(/```/g, '').trim();
        const llmResult = JSON.parse(cleanText) as { attackVector: string; severity: string; summary: string }[];

        if (!Array.isArray(llmResult)) {
            throw new Error('LLM output could not be parsed into a JSON array.');
        }

        // Map intelligence fields to threat logs and build Mongoose docs
        const dbDocs = batch.map((item, idx) => {
            const llmAnalysis = llmResult[idx] || {
                attackVector: 'Uncategorized Anomaly',
                severity: 'HIGH',
                summary: 'AI Security classification was unavailable for this record.'
            };

            return {
                clientIp: item.payload.clientIp,
                endpoint: item.payload.endpoint,
                method: item.payload.method,
                timestamp: new Date(item.payload.timestamp),
                rawBody: item.payload.rawBody,
                attackVector: llmAnalysis.attackVector,
                severity: llmAnalysis.severity,
                summary: llmAnalysis.summary,
                createdAt: new Date()
            };
        });

        // Write batch in a single database round-trip
        await ThreatLogModel.insertMany(dbDocs);
        console.log(`💾 [Database] Successfully wrote ${dbDocs.length} updated intelligence records to MongoDB.`);

        // Acknowledge all messages cleanly from RabbitMQ
        for (const item of batch) {
            channel?.ack(item.msg);
        }
        console.log(`🐇 [Queue] Acknowledged ${batch.length} threat logs in RabbitMQ.`);
    } catch (error: any) {
        console.error('[Worker Analytics Fault - Releasing Messages Back to Queue]');
        console.error('Error Trace:', error.message || error);

        // Fail-Open resiliency: return all messages to queue with requeue=true
        for (const item of batch) {
            try {
                channel?.nack(item.msg, false, true);
            } catch (nackError: any) {
                console.error('🐇 [Queue Nack Failure] Failed to release message:', nackError.message);
            }
        }
    }
};

/**
 * Boots the daemon process, connecting to MongoDB and RabbitMQ, and listens for threats.
 */
const startWorker = async (): Promise<void> => {
    try {
        console.log('🔌 Connecting to MongoDB...');
        await mongoose.connect(MONGO_URI);
        console.log('💾 Connected to MongoDB successfully.');

        console.log('🔌 Connecting to RabbitMQ...');
        connection = await amqplib.connect(RABBITMQ_URL);
        channel = await connection.createChannel();

        // Assert durable queue to guarantee it exists
        await channel.assertQueue(QUEUE_NAME, {
            durable: true
        });

        // Set prefetch count of 20
        await channel.prefetch(20);

        console.log('🐇 Connected to RabbitMQ successfully. Prefetch set to 20.');

        // Rolling interval timer checking if 30s elapsed since last successful flush
        setInterval(async () => {
            if (messageBuffer.length > 0 && (Date.now() - lastFlushTime >= 30000)) {
                console.log('⏱️ [Timer Flush] 30 seconds rolling timer elapsed. Flushing buffer...');
                await flushBuffer();
            }
        }, 1000);

        console.log('📥 Start consuming messages from blocked_threats_queue...');
        
        await channel.consume(QUEUE_NAME, async (msg) => {
            if (!msg) {
                return;
            }

            try {
                const payload = JSON.parse(msg.content.toString());
                messageBuffer.push({ msg, payload });

                console.log(`📥 Received threat log. Buffer status: ${messageBuffer.length}/10`);

                // Capacity check: Flush when we collect exactly 10 threat records
                if (messageBuffer.length >= 10) {
                    console.log('🚀 [Capacity Flush] Buffer reached 10 records. Triggering flush...');
                    await flushBuffer();
                }
            } catch (err: any) {
                console.error('❌ [Consume Error] Malformed message rejected:', err.message);
                // Acknowledge malformed JSON messages immediately to avoid infinite queue loops
                channel?.ack(msg);
            }
        }, {
            noAck: false // We must acknowledge manually using channel.ack
        });

        console.log('🛡️ AegisGate Control Plane Background Worker is fully online.');
    } catch (error: any) {
        console.error('❌ [Worker Initialization Failure] Severe boot failure:', error.message);
        process.exit(1);
    }
};

startWorker();
